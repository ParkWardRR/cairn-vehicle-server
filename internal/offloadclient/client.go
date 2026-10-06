// Package offloadclient is the phone's half of BLE bundle offload
// (docs/ble-offload.md): it pulls sealed bundles off a dongle, relays them to the
// server, and hands the signed receipt back.
//
// It is independent of how bytes reach the dongle. A Transport carries them: the
// cairn-phone tool supplies CoreBluetooth, and the end-to-end test supplies a pipe
// to the real firmware protocol code running on the host. That independence is
// the point, because it lets the whole path (this client, the dongle's protocol
// module and the server's relay) be exercised without a radio.
//
// This is also a reference for the iOS app: same framing, same loop, same retry
// rules, in a language that can be run against the real firmware code.
package offloadclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"time"
)

// Control opcodes and statuses, from the spec.
const (
	opList        = 0x01
	opGetManifest = 0x02
	opRead        = 0x03
	opPutReceipt  = 0x04
	opAbort       = 0x05
	indDone       = 0x86

	maxRead = 65536
)

// Status is a dongle status code.
type Status uint8

const (
	StatusOK               Status = 0
	StatusBusy             Status = 1
	StatusUnknownBundle    Status = 2
	StatusBadArgument      Status = 3
	StatusTripActive       Status = 4
	StatusIOError          Status = 5
	StatusBadReceiptLength Status = 6
	StatusNoTransfer       Status = 7
)

func (s Status) String() string {
	names := []string{"OK", "BUSY", "UNKNOWN_BUNDLE", "BAD_ARGUMENT", "TRIP_ACTIVE", "IO_ERROR", "BAD_RECEIPT_LENGTH", "NO_TRANSFER"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("STATUS(%d)", uint8(s))
}

// DeviceError is a refusal from the dongle.
type DeviceError struct {
	Op     string
	Status Status
}

func (e *DeviceError) Error() string { return fmt.Sprintf("dongle refused %s: %s", e.Op, e.Status) }

// ErrTripActive is returned when the dongle is capturing a trip. It is normal:
// try again after the drive.
var ErrTripActive = errors.New("the dongle is capturing a trip; try again after the drive")

// Outcome is what the dongle did with a receipt.
type Outcome uint8

const (
	OutcomePruned    Outcome = 0
	OutcomeRetained  Outcome = 1
	OutcomeBadSig    Outcome = 2
	OutcomeWrongRoot Outcome = 3
	OutcomeNoKey     Outcome = 4
)

func (o Outcome) String() string {
	return [...]string{"pruned", "retained (prune pending)", "REJECTED: bad signature", "REJECTED: wrong content root", "not verified: no key pinned in firmware"}[min(int(o), 4)]
}

// Transport carries bytes to and from the dongle. Inbound bytes are delivered by
// calling Client.OnControl and Client.OnData.
type Transport interface {
	// WriteControl writes to OFFLOAD_CONTROL (write with response).
	WriteControl(b []byte) error
	// WriteData writes to OFFLOAD_DATA (write without response).
	WriteData(b []byte) error
	// MTU is the negotiated ATT MTU.
	MTU() int
}

// Entry is one bundle the dongle lists.
type Entry struct {
	ID          [16]byte
	StreamBytes uint64
	ManifestLen int
	ChunkCount  int
	State       uint8 // 0 sealed, awaiting a receipt; 1 receipt verified, prune pending
}

// Client speaks the offload protocol to one dongle. One operation at a time.
type Client struct {
	t Transport

	// Timeouts. The defaults suit a real radio; the host test shortens them.
	ControlTimeout time.Duration
	StreamTimeout  time.Duration
	// ReadPiece bounds one READ. Smaller pieces lose less to a dropped notification.
	ReadPiece int
	// Retries is how many times a stream with a bad length, CRC or sequence is
	// re-requested before giving up.
	Retries int

	mu      sync.Mutex
	rid     uint8
	resp    chan []byte
	done    chan []byte
	dataBuf []byte
	dataSeq uint16
	dataBad error
}

// New returns a client over t.
func New(t Transport) *Client {
	return &Client{
		t: t, ControlTimeout: 5 * time.Second, StreamTimeout: 30 * time.Second,
		ReadPiece: 16384, Retries: 3,
		resp: make(chan []byte, 16), done: make(chan []byte, 4),
	}
}

// OnControl is called with every indication from OFFLOAD_CONTROL.
func (c *Client) OnControl(b []byte) {
	if len(b) < 3 {
		return
	}
	cp := append([]byte(nil), b...)
	if cp[0] == indDone {
		select {
		case c.done <- cp:
		default:
		}
		return
	}
	select {
	case c.resp <- cp:
	default:
	}
}

// OnData is called with every notification from OFFLOAD_DATA.
func (c *Client) OnData(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) < 3 {
		c.dataBad = errors.New("empty data frame")
		return
	}
	if seq := binary.LittleEndian.Uint16(b); seq != c.dataSeq {
		c.dataBad = fmt.Errorf("data frame seq %d, want %d (a notification was lost)", seq, c.dataSeq)
		return
	}
	c.dataSeq++
	c.dataBuf = append(c.dataBuf, b[2:]...)
}

func (c *Client) drain() {
	for {
		select {
		case <-c.resp:
		case <-c.done:
		default:
			return
		}
	}
}

// send issues a request and returns the response's status and payload.
func (c *Client) send(ctx context.Context, op uint8, payload []byte, name string) (Status, []byte, uint8, error) {
	c.rid++
	rid := c.rid
	if err := c.t.WriteControl(append([]byte{op, rid}, payload...)); err != nil {
		return 0, nil, rid, err
	}
	st, pl, err := c.await(ctx, op, rid, c.ControlTimeout, name)
	return st, pl, rid, err
}

// await waits for the response (op|0x80, rid).
func (c *Client) await(ctx context.Context, op, rid uint8, d time.Duration, name string) (Status, []byte, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case m := <-c.resp:
			if m[0] == op|0x80 && m[1] == rid {
				return Status(m[2]), m[3:], nil
			}
			// A stale response from an abandoned request: ignore it.
		case <-timer.C:
			return 0, nil, fmt.Errorf("%s: no response from the dongle", name)
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}
}

func refuse(name string, st Status) error {
	if st == StatusTripActive {
		return fmt.Errorf("%w (%s)", ErrTripActive, name)
	}
	return &DeviceError{Op: name, Status: st}
}

// List returns every sealed bundle on the dongle.
func (c *Client) List(ctx context.Context) ([]Entry, error) {
	var all []Entry
	first := 0
	for {
		c.drain()
		arg := make([]byte, 2)
		binary.LittleEndian.PutUint16(arg, uint16(first))
		st, pl, _, err := c.send(ctx, opList, arg, "LIST")
		if err != nil {
			return nil, err
		}
		if st != StatusOK {
			return nil, refuse("LIST", st)
		}
		if len(pl) < 5 {
			return nil, errors.New("LIST: short response")
		}
		total := int(binary.LittleEndian.Uint16(pl))
		n := int(pl[4])
		if len(pl) != 5+n*29 {
			return nil, fmt.Errorf("LIST: %d entries need %d bytes, got %d", n, 5+n*29, len(pl))
		}
		for i := 0; i < n; i++ {
			e := pl[5+i*29:]
			var ent Entry
			copy(ent.ID[:], e[:16])
			ent.StreamBytes = binary.LittleEndian.Uint64(e[16:])
			ent.ManifestLen = int(binary.LittleEndian.Uint16(e[24:]))
			ent.ChunkCount = int(binary.LittleEndian.Uint16(e[26:]))
			ent.State = e[28]
			all = append(all, ent)
		}
		first += n
		if n == 0 || first >= total {
			return all, nil
		}
	}
}

// stream runs a data-producing request and returns the verified bytes.
func (c *Client) stream(ctx context.Context, op uint8, arg []byte, want int, name string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		c.drain()
		c.mu.Lock()
		c.dataBuf, c.dataSeq, c.dataBad = nil, 0, nil
		c.mu.Unlock()

		st, _, rid, err := c.send(ctx, op, arg, name)
		if err != nil {
			return nil, err
		}
		if st != StatusOK {
			return nil, refuse(name, st)
		}

		var done []byte
		timer := time.NewTimer(c.StreamTimeout)
		select {
		case done = <-c.done:
		case <-timer.C:
			timer.Stop()
			lastErr = fmt.Errorf("%s: the transfer never finished", name)
			_ = c.Abort(ctx)
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
		timer.Stop()

		if len(done) != 11 || done[1] != rid {
			lastErr = fmt.Errorf("%s: malformed or stale done indication", name)
			continue
		}
		if Status(done[2]) != StatusOK {
			return nil, refuse(name, Status(done[2]))
		}

		c.mu.Lock()
		got, bad := append([]byte(nil), c.dataBuf...), c.dataBad
		c.mu.Unlock()

		sent := binary.LittleEndian.Uint32(done[3:])
		sum := binary.LittleEndian.Uint32(done[7:])
		switch {
		case bad != nil:
			lastErr = fmt.Errorf("%s: %w", name, bad)
		case int(sent) != len(got) || len(got) != want:
			lastErr = fmt.Errorf("%s: received %d bytes, dongle says it sent %d, wanted %d", name, len(got), sent, want)
		case crc32.ChecksumIEEE(got) != sum:
			lastErr = fmt.Errorf("%s: CRC mismatch (a byte was corrupted in flight)", name)
		default:
			return got, nil
		}
	}
	return nil, lastErr
}

// Manifest returns manifest.cbor and manifest.sig for a bundle.
func (c *Client) Manifest(ctx context.Context, e Entry) (manifest, sig []byte, err error) {
	want := e.ManifestLen + 64
	b, err := c.stream(ctx, opGetManifest, e.ID[:], want, "GET_MANIFEST")
	if err != nil {
		return nil, nil, err
	}
	return b[:e.ManifestLen], b[e.ManifestLen:], nil
}

// ReadRange returns bytes [offset, offset+length) of the bundle byte stream,
// fetched in pieces and concatenated.
func (c *Client) ReadRange(ctx context.Context, id [16]byte, offset uint64, length uint32) ([]byte, error) {
	out := make([]byte, 0, length)
	for uint32(len(out)) < length {
		n := length - uint32(len(out))
		if int(n) > c.ReadPiece {
			n = uint32(c.ReadPiece)
		}
		if n > maxRead {
			n = maxRead
		}
		arg := make([]byte, 28)
		copy(arg, id[:])
		binary.LittleEndian.PutUint64(arg[16:], offset+uint64(len(out)))
		binary.LittleEndian.PutUint32(arg[24:], n)
		piece, err := c.stream(ctx, opRead, arg, int(n), "READ")
		if err != nil {
			return nil, err
		}
		out = append(out, piece...)
	}
	return out, nil
}

// PutReceipt hands a server receipt to the dongle and returns what it did.
func (c *Client) PutReceipt(ctx context.Context, id [16]byte, receipt []byte) (Outcome, error) {
	c.drain()
	arg := make([]byte, 18)
	copy(arg, id[:])
	binary.LittleEndian.PutUint16(arg[16:], uint16(len(receipt)))
	st, _, rid, err := c.send(ctx, opPutReceipt, arg, "PUT_RECEIPT")
	if err != nil {
		return 0, err
	}
	if st != StatusOK {
		return 0, refuse("PUT_RECEIPT", st)
	}

	piece := c.t.MTU() - 3 - 2
	if piece < 20 {
		piece = 20
	}
	for seq, at := 0, 0; at < len(receipt); seq++ {
		n := min(piece, len(receipt)-at)
		f := make([]byte, 2+n)
		binary.LittleEndian.PutUint16(f, uint16(seq))
		copy(f[2:], receipt[at:at+n])
		if err := c.t.WriteData(f); err != nil {
			return 0, err
		}
		at += n
	}

	st, pl, err := c.await(ctx, opPutReceipt, rid, c.ControlTimeout, "PUT_RECEIPT outcome")
	if err != nil {
		return 0, err
	}
	if st != StatusOK {
		return 0, refuse("PUT_RECEIPT", st)
	}
	if len(pl) != 1 {
		return 0, errors.New("PUT_RECEIPT: no outcome byte")
	}
	return Outcome(pl[0]), nil
}

// Abort cancels whatever the dongle is doing.
func (c *Client) Abort(ctx context.Context) error {
	_, _, _, err := c.send(ctx, opAbort, nil, "ABORT")
	return err
}

// ─── the relay ──────────────────────────────────────────────────────────────

// Chunk is one chunk the server still needs.
type Chunk struct {
	Index  uint32 `json:"index"`
	Offset uint64 `json:"offset"`
	Length uint32 `json:"length"`
	SHA256 string `json:"sha256"`
}

// OfferResult is the server's answer to an offer.
type OfferResult struct {
	BundleID         string  `json:"bundle_id"`
	MissingChunks    []Chunk `json:"missing_chunks"`
	ReceiptAvailable bool    `json:"receipt_available"`
}

// Relay is the server side of the offload.
type Relay interface {
	Offer(ctx context.Context, manifest, sig []byte) (*OfferResult, error)
	PutChunk(ctx context.Context, bundleID string, sha256Hex string, data []byte) error
	Commit(ctx context.Context, bundleID string) ([]byte, error)
}

// Result is what happened to one bundle.
type Result struct {
	BundleID string
	Outcome  Outcome
	Chunks   int
	Bytes    int
	Err      error
}

// Offload moves every sealed bundle the dongle lists through the relay and hands
// the receipts back. One bundle's failure does not stop the others. A TRIP_ACTIVE
// refusal ends the run (it is not a failure: there is simply nothing to do yet).
func (c *Client) Offload(ctx context.Context, relay Relay, log func(string, ...any)) ([]Result, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	entries, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	log("%d bundle(s) on the dongle", len(entries))

	var out []Result
	for _, e := range entries {
		if e.State != 0 {
			log("%x already has a verified receipt; the dongle will finish the prune", e.ID)
			continue
		}
		r := c.one(ctx, relay, e, log)
		out = append(out, r)
		if errors.Is(r.Err, ErrTripActive) {
			return out, r.Err
		}
	}
	return out, nil
}

func (c *Client) one(ctx context.Context, relay Relay, e Entry, log func(string, ...any)) (r Result) {
	r.BundleID = hex.EncodeToString(e.ID[:])
	fail := func(err error) Result { r.Err = err; return r }

	manifest, sig, err := c.Manifest(ctx, e)
	if err != nil {
		return fail(err)
	}
	offer, err := relay.Offer(ctx, manifest, sig)
	if err != nil {
		return fail(fmt.Errorf("offer: %w", err))
	}
	log("%s: %d chunk(s) missing on the server", r.BundleID[:8], len(offer.MissingChunks))

	for _, ch := range offer.MissingChunks {
		data, err := c.ReadRange(ctx, e.ID, ch.Offset, ch.Length)
		if err != nil {
			return fail(fmt.Errorf("read chunk %d: %w", ch.Index, err))
		}
		// Check the digest before uploading: a chunk the server will refuse is not
		// worth the airtime, and a mismatch here means the dongle's bytes changed.
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != ch.SHA256 {
			return fail(fmt.Errorf("chunk %d does not hash to the digest in the manifest", ch.Index))
		}
		if err := relay.PutChunk(ctx, offer.BundleID, ch.SHA256, data); err != nil {
			return fail(fmt.Errorf("upload chunk %d: %w", ch.Index, err))
		}
		r.Chunks++
		r.Bytes += len(data)
	}

	receipt, err := relay.Commit(ctx, offer.BundleID)
	if err != nil {
		return fail(fmt.Errorf("commit: %w", err))
	}
	log("%s: committed, receipt %d bytes", r.BundleID[:8], len(receipt))

	out, err := c.PutReceipt(ctx, e.ID, receipt)
	if err != nil {
		return fail(fmt.Errorf("hand the receipt back: %w", err))
	}
	r.Outcome = out
	log("%s: dongle says %s", r.BundleID[:8], out)
	if out == OutcomeBadSig || out == OutcomeWrongRoot {
		return fail(fmt.Errorf("the dongle rejected the server's receipt: %s", out))
	}
	return r
}
