// Package mqtt publishes semantic device state to a local broker.
//
// What it publishes is deliberately narrow: trip boundaries, detected events,
// storage warnings, backlog changes. Never raw samples. Publishing every
// position or IMU reading would turn Home Assistant into an accidental
// telemetry database, which is both a poor fit for its storage model and a
// privacy hazard — the review was explicit about this and it is worth holding.
//
// Every message carries event_id, occurred_at, published_at and a schema
// version. Because event_id is derived deterministically from the bundle, kind
// and sequence, a re-decode republishes the *same* identity: a consumer can
// deduplicate with no coordination, which is what makes the stream idempotent
// rather than merely at-least-once.
//
// A raw MQTT 3.1.1 client, no external dependency. The protocol surface needed
// here is small, and a broker on the LAN is the only peer.
package mqtt

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/worker"
)

// SchemaVersion is carried in every payload, so a consumer can tell which
// contract produced a message.
const SchemaVersion = 2

// Config configures a Publisher.
type Config struct {
	// Addr is the broker, host:port. Empty disables publishing entirely.
	Addr string

	// ClientID identifies this publisher to the broker.
	ClientID string

	// TopicPrefix defaults to "cairn".
	TopicPrefix string

	// Timeout bounds a connect or publish.
	Timeout time.Duration
}

// Publisher sends semantic events to MQTT.
type Publisher struct {
	cfg Config

	mu     sync.Mutex
	conn   net.Conn
	packet uint16
}

// New creates a Publisher. A zero Addr yields a disabled publisher, which is a
// valid configuration: MQTT is an optional edge, and a drive must not depend on
// a broker being reachable.
func New(cfg Config) *Publisher {
	if cfg.TopicPrefix == "" {
		cfg.TopicPrefix = "cairn"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "cairn-worker"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Publisher{cfg: cfg}
}

// Enabled reports whether a broker is configured.
func (p *Publisher) Enabled() bool { return p.cfg.Addr != "" }

// Close drops the broker connection.
func (p *Publisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

// payload is the wire shape. Every field exists so a consumer can act on the
// message without querying back.
type payload struct {
	SchemaVersion int    `json:"schema_version"`
	EventID       string `json:"event_id"`
	Kind          string `json:"kind"`
	DeviceID      string `json:"device_id"`
	TripID        string `json:"trip_id,omitempty"`

	// OccurredAt is when the vehicle did the thing. PublishedAt is when we said
	// so. They differ by however long the device was parked away from home,
	// which can be days — so a consumer must not treat arrival as occurrence.
	OccurredAt  time.Time `json:"occurred_at"`
	PublishedAt time.Time `json:"published_at"`

	Lat *float64 `json:"lat,omitempty"`
	Lon *float64 `json:"lon,omitempty"`

	Detail map[string]any `json:"detail,omitempty"`

	// LocalOnly is a standing assertion that this data never left the LAN.
	LocalOnly bool `json:"local_only"`
}

// Publish sends one semantic event.
//
// Implements worker.Publisher.
func (p *Publisher) Publish(ctx context.Context, ev worker.PublishableEvent) error {
	if !p.Enabled() {
		return nil
	}

	body, err := json.Marshal(payload{
		SchemaVersion: SchemaVersion,
		EventID:       ev.EventID,
		Kind:          ev.Kind,
		DeviceID:      ev.DeviceID,
		TripID:        ev.TripID,
		OccurredAt:    ev.OccurredAt.UTC(),
		PublishedAt:   time.Now().UTC(),
		Lat:           ev.Lat,
		Lon:           ev.Lon,
		Detail:        ev.Detail,
		LocalOnly:     true,
	})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	topic := fmt.Sprintf("%s/vehicle/%s/%s", p.cfg.TopicPrefix, ev.DeviceID, ev.Kind)
	return p.publishRaw(ctx, topic, body, true)
}

// PublishBacklog announces the decode backlog.
//
// Semantic state rather than an event: retained, so a consumer that subscribes
// later immediately learns the current value instead of waiting for the next
// change.
func (p *Publisher) PublishBacklog(ctx context.Context, pending int) error {
	if !p.Enabled() {
		return nil
	}

	body, err := json.Marshal(map[string]any{
		"schema_version": SchemaVersion,
		"kind":           "upload_backlog_changed",
		"pending":        pending,
		"published_at":   time.Now().UTC(),
		"local_only":     true,
	})
	if err != nil {
		return err
	}

	return p.publishRaw(ctx, p.cfg.TopicPrefix+"/server/backlog", body, true)
}

// PublishAvailability announces that the server is up, retained so a consumer
// sees it on subscribe.
func (p *Publisher) PublishAvailability(ctx context.Context, online bool) error {
	if !p.Enabled() {
		return nil
	}

	state := "offline"
	if online {
		state = "online"
	}
	return p.publishRaw(ctx, p.cfg.TopicPrefix+"/server/availability", []byte(state), true)
}

// ─── minimal MQTT 3.1.1 ─────────────────────────────────────────────────────

func (p *Publisher) publishRaw(ctx context.Context, topic string, body []byte, retain bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureConnected(ctx); err != nil {
		return err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(p.cfg.Timeout)
	}
	if err := p.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}

	// QoS 0: the broker is on the LAN, and the durable record of every event is
	// in Postgres with its published_at. Losing a notification is recoverable;
	// blocking a decode on an acknowledgement is not worth it.
	var flags byte
	if retain {
		flags |= 0x01
	}

	var varHeader []byte
	varHeader = appendString(varHeader, topic)

	remaining := len(varHeader) + len(body)
	pkt := []byte{0x30 | flags}
	pkt = appendRemainingLength(pkt, remaining)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, body...)

	if _, err := p.conn.Write(pkt); err != nil {
		// Drop the connection so the next attempt reconnects rather than
		// writing into a broken pipe.
		_ = p.conn.Close()
		p.conn = nil
		return fmt.Errorf("publish to %s: %w", topic, err)
	}

	return nil
}

func (p *Publisher) ensureConnected(ctx context.Context) error {
	if p.conn != nil {
		return nil
	}

	d := net.Dialer{Timeout: p.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", p.cfg.Addr)
	if err != nil {
		return fmt.Errorf("dial broker %s: %w", p.cfg.Addr, err)
	}

	if err := conn.SetDeadline(time.Now().Add(p.cfg.Timeout)); err != nil {
		_ = conn.Close()
		return err
	}

	// CONNECT: clean session, 60 s keepalive.
	var varHeader []byte
	varHeader = appendString(varHeader, "MQTT")
	varHeader = append(varHeader, 0x04) // protocol level 4 = 3.1.1
	varHeader = append(varHeader, 0x02) // clean session
	varHeader = binary.BigEndian.AppendUint16(varHeader, 60)
	varHeader = appendString(varHeader, p.cfg.ClientID)

	pkt := []byte{0x10}
	pkt = appendRemainingLength(pkt, len(varHeader))
	pkt = append(pkt, varHeader...)

	if _, err := conn.Write(pkt); err != nil {
		_ = conn.Close()
		return fmt.Errorf("send CONNECT: %w", err)
	}

	// CONNACK is 4 bytes.
	ack := make([]byte, 4)
	if _, err := conn.Read(ack); err != nil {
		_ = conn.Close()
		return fmt.Errorf("read CONNACK: %w", err)
	}
	if ack[0] != 0x20 || ack[3] != 0x00 {
		_ = conn.Close()
		return fmt.Errorf("broker refused the connection: return code %d", ack[3])
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return err
	}

	p.conn = conn
	return nil
}

func appendString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(s)))
	return append(dst, s...)
}

// appendRemainingLength writes MQTT's variable-length integer encoding.
func appendRemainingLength(dst []byte, n int) []byte {
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if n == 0 {
			return dst
		}
	}
}
