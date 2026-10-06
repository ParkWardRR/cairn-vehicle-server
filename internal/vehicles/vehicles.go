// Package vehicles models cars and which recorder is fitted to which car.
//
// Until v3 a vehicle was implied by the dongle that uploaded: one device, one
// car, no way to say otherwise. That breaks the first time a second car joins,
// or the dongle moves between cars — a trip would silently land under whichever
// vehicle the device was last associated with. So the vehicle is now explicit
// and carried by the data itself: every bundle names a vehicle and the
// assignment under which it was captured, and intake refuses bundles whose
// assignment this registry does not recognise.
//
// # Assignments, and why they are not checked against the clock
//
// A device is fitted to a vehicle by an assignment. Reassigning ends the old
// one and starts a new one. The obvious validity test — "was the assignment
// active at the bundle's capture time?" — is the wrong one here. Capture time
// is a GNSS-derived estimate with its own uncertainty and can be absent
// entirely (invariant 3: ordering truth is never wall-clock), and a device
// legitimately uploads a bundle captured under the *old* assignment after the
// administrator has already moved it, because it has not yet heard about the
// move.
//
// The test used instead is order, expressed in the device's own monotonic
// bundle counter: a bundle is stale if it claims an assignment that the server
// has already seen superseded by a newer one at a lower counter. That is
// exactly "the device used the old identity after it had demonstrably switched
// to the new one", which is the only sequence that indicates a mistake or an
// attack, and it needs no trusted clock.
//
// The registry is a JSON file for the same reason the device registry is: ingest
// must keep receipting trips through a database outage.
package vehicles

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/jsonstore"
)

var (
	// ErrUnknownVehicle means no vehicle has this ID.
	ErrUnknownVehicle = errors.New("vehicle not found")
	// ErrVehicleArchived means the vehicle was retired and accepts no new data.
	ErrVehicleArchived = errors.New("vehicle is archived")
	// ErrVehicleBusy means another device already holds the vehicle. A car has
	// one recorder at a time: two would capture the same drive twice under
	// different identities.
	ErrVehicleBusy = errors.New("vehicle is already assigned to another device")
	// ErrAssignmentUnknown means a bundle names an assignment this server never
	// issued.
	ErrAssignmentUnknown = errors.New("assignment not recognised")
	// ErrAssignmentMismatch means the assignment exists but belongs to a
	// different device or vehicle than the bundle claims.
	ErrAssignmentMismatch = errors.New("assignment does not match the bundle's device and vehicle")
	// ErrAssignmentSuperseded means the device used an old assignment after it
	// had already used a newer one.
	ErrAssignmentSuperseded = errors.New("assignment was superseded before this bundle was sealed")
)

// Vehicle is one physical car.
type Vehicle struct {
	ID          string `json:"id"` // hex of a 16-byte UUIDv7
	OwnerID     string `json:"owner_id,omitempty"`
	DisplayName string `json:"display_name"`
	Year        int    `json:"year,omitempty"`
	Make        string `json:"make,omitempty"`
	Model       string `json:"model,omitempty"`

	// EngineCode is the engine family (e.g. "B58"). It is a label, not an
	// identity: two cars can share one, so it must never be used to tell
	// vehicles apart.
	EngineCode string `json:"engine_code,omitempty"`

	// VINCiphertext is the VIN sealed with the registry's key; VINLast4 is what
	// logs and UI may show. The full VIN identifies one car to anyone who sees
	// it, so it is never stored or logged in the clear.
	VINCiphertext string `json:"vin_ciphertext,omitempty"`
	VINLast4      string `json:"vin_last4,omitempty"`

	// Tunes is the car's tune history, oldest first by date. It is what lets the
	// store say how boost and fuel trim moved before and after a change.
	Tunes []Tune `json:"tunes,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ArchivedAt time.Time `json:"archived_at,omitzero"`
}

// clone copies the vehicle and what it holds, so a caller cannot edit the registry
// through a returned value.
func (v *Vehicle) clone() *Vehicle {
	c := *v
	c.Tunes = append([]Tune(nil), v.Tunes...)
	return &c
}

// Archived reports whether the vehicle has been retired.
func (v *Vehicle) Archived() bool { return !v.ArchivedAt.IsZero() }

// Assignment fits one device to one vehicle for an interval.
type Assignment struct {
	ID        string `json:"id"` // hex of a 16-byte UUIDv7
	DeviceID  string `json:"device_id"`
	VehicleID string `json:"vehicle_id"`

	// Seq orders a device's assignments. Starts and ends are wall-clock and are
	// kept for people; Seq is what the supersession check compares.
	Seq int `json:"seq"`

	StartsAt   time.Time `json:"starts_at"`
	EndsAt     time.Time `json:"ends_at,omitzero"`
	AssignedBy string    `json:"assigned_by,omitempty"`

	// FirstCounter and LastCounter are the lowest and highest device bundle
	// counters the server has accepted under this assignment. FirstCounter is
	// what later lets the server recognise a stale reuse of an older
	// assignment.
	FirstCounter uint64 `json:"first_counter,omitempty"`
	LastCounter  uint64 `json:"last_counter,omitempty"`
}

// Open reports whether the assignment has not been ended.
func (a *Assignment) Open() bool { return a.EndsAt.IsZero() }

type document struct {
	Vehicles    []*Vehicle    `json:"vehicles"`
	Assignments []*Assignment `json:"assignments"`
}

// Registry is the vehicle and assignment store.
type Registry struct {
	store  *jsonstore.Store[document]
	vinKey [32]byte
	now    func() time.Time
}

// Option configures a Registry.
type Option func(*Registry)

// WithClock replaces the time source, so a test or a vector generator gets
// reproducible assignment and archive times.
func WithClock(now func() time.Time) Option { return func(r *Registry) { r.now = now } }

// Open loads the registry at path. vinKeyPath holds the 32-byte key that seals
// VINs; it is created (mode 0600) when absent.
func Open(path, vinKeyPath string, opts ...Option) (*Registry, error) {
	store, err := jsonstore.Open(path, func() document { return document{} })
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(vinKeyPath)
	if err != nil {
		return nil, err
	}
	r := &Registry{store: store, vinKey: key, now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

func loadOrCreateKey(path string) ([32]byte, error) {
	var key [32]byte
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		raw = []byte(strings.TrimSpace(string(raw)))
		b, derr := hex.DecodeString(string(raw))
		if derr != nil || len(b) != 32 {
			return key, fmt.Errorf("vehicle key %s must hold 64 hex characters", filepath.Base(path))
		}
		copy(key[:], b)
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return key, fmt.Errorf("read vehicle key: %w", err)
	}

	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate vehicle key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("create key dir: %w", err)
	}
	// O_EXCL: two processes racing to create the first key must not each
	// believe theirs won, or one would seal VINs nobody can open.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateKey(path)
		}
		return key, fmt.Errorf("create vehicle key: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(key[:]) + "\n"); err != nil {
		return key, fmt.Errorf("write vehicle key: %w", err)
	}
	return key, f.Sync()
}

// NewVehicleSpec describes a vehicle to create.
type NewVehicleSpec struct {
	// ID is optional (32 hex characters). Normal use leaves it empty and gets a
	// fresh UUIDv7; it exists so a registry can be restored from a backup, and
	// so tests can use the fixed identifiers their synthetic bundles carry.
	ID string

	OwnerID     string
	DisplayName string
	Year        int
	Make        string
	Model       string
	EngineCode  string

	// VIN is optional. It is sealed immediately and only its last four
	// characters are kept readable.
	VIN string
}

// CreateVehicle adds a vehicle.
func (r *Registry) CreateVehicle(spec NewVehicleSpec) (*Vehicle, error) {
	if strings.TrimSpace(spec.DisplayName) == "" {
		return nil, errors.New("a vehicle needs a display name")
	}

	idHex := strings.ToLower(spec.ID)
	if idHex == "" {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		idHex = hex.EncodeToString(id[:])
	} else if raw, err := hex.DecodeString(idHex); err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("vehicle ID must be 32 hex characters, got %q", spec.ID)
	}
	v := &Vehicle{
		ID:          idHex,
		OwnerID:     spec.OwnerID,
		DisplayName: spec.DisplayName,
		Year:        spec.Year,
		Make:        spec.Make,
		Model:       spec.Model,
		EngineCode:  spec.EngineCode,
		CreatedAt:   r.now(),
	}

	if vin := strings.ToUpper(strings.TrimSpace(spec.VIN)); vin != "" {
		if len(vin) != 17 {
			return nil, fmt.Errorf("a VIN is 17 characters, got %d", len(vin))
		}
		ct, err := r.sealVIN(vin)
		if err != nil {
			return nil, err
		}
		v.VINCiphertext = ct
		v.VINLast4 = vin[len(vin)-4:]
	}

	err := r.store.Update(func(d *document) error {
		for _, existing := range d.Vehicles {
			if existing.ID == v.ID {
				return fmt.Errorf("a vehicle with ID %s already exists", v.ID)
			}
		}
		d.Vehicles = append(d.Vehicles, v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return v.clone(), nil
}

// Vehicle returns one vehicle.
func (r *Registry) Vehicle(id string) (*Vehicle, error) {
	var out *Vehicle
	r.store.View(func(d *document) {
		for _, v := range d.Vehicles {
			if strings.EqualFold(v.ID, id) {
				out = v.clone()
				return
			}
		}
	})
	if out == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownVehicle, id)
	}
	return out, nil
}

// Vehicles lists every vehicle, archived ones last.
func (r *Registry) Vehicles() []*Vehicle {
	var out []*Vehicle
	r.store.View(func(d *document) {
		for _, v := range d.Vehicles {
			out = append(out, v.clone())
		}
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Archived() != out[j].Archived() {
			return !out[i].Archived()
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Archive retires a vehicle. Its history stays; it accepts no new bundles.
func (r *Registry) Archive(id string) error {
	return r.store.Update(func(d *document) error {
		for _, v := range d.Vehicles {
			if strings.EqualFold(v.ID, id) {
				if !v.Archived() {
					v.ArchivedAt = r.now()
				}
				// Ending the open assignment frees the recorder for another car.
				for _, a := range d.Assignments {
					if a.VehicleID == v.ID && a.Open() {
						a.EndsAt = r.now()
					}
				}
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrUnknownVehicle, id)
	})
}

// RevealVIN opens the sealed VIN. It exists for the administrative CLI; nothing
// on the request path calls it.
func (r *Registry) RevealVIN(id string) (string, error) {
	v, err := r.Vehicle(id)
	if err != nil {
		return "", err
	}
	if v.VINCiphertext == "" {
		return "", nil
	}
	return r.openVIN(v.VINCiphertext)
}

func (r *Registry) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(r.vinKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (r *Registry) sealVIN(vin string) (string, error) {
	gcm, err := r.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vin nonce: %w", err)
	}
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(vin), []byte("cairn/vin/v1"))), nil
}

func (r *Registry) openVIN(sealed string) (string, error) {
	raw, err := hex.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("vin ciphertext is not hex: %w", err)
	}
	gcm, err := r.aead()
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("vin ciphertext is truncated")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte("cairn/vin/v1"))
	if err != nil {
		return "", fmt.Errorf("vin cannot be opened with this key: %w", err)
	}
	return string(pt), nil
}

// Assign fits a device to a vehicle, ending the device's previous assignment.
//
// Reassignment is an explicit administrative act rather than something a device
// can assert, so a dongle moved between cars cannot quietly deposit trips under
// the wrong one.
func (r *Registry) Assign(deviceID, vehicleID, assignedBy string) (*Assignment, error) {
	return r.AssignWithID("", deviceID, vehicleID, assignedBy)
}

// AssignWithID is Assign with a caller-chosen assignment ID (32 hex
// characters), for restoring a registry and for tests whose synthetic bundles
// carry a fixed one. An empty ID generates a fresh UUIDv7.
func (r *Registry) AssignWithID(assignmentID, deviceID, vehicleID, assignedBy string) (*Assignment, error) {
	deviceID = strings.ToLower(deviceID)
	assignmentID = strings.ToLower(assignmentID)
	if assignmentID != "" {
		if raw, err := hex.DecodeString(assignmentID); err != nil || len(raw) != 16 {
			return nil, fmt.Errorf("assignment ID must be 32 hex characters, got %q", assignmentID)
		}
	}

	var created *Assignment
	err := r.store.Update(func(d *document) error {
		var vehicle *Vehicle
		for _, v := range d.Vehicles {
			if strings.EqualFold(v.ID, vehicleID) {
				vehicle = v
			}
		}
		if vehicle == nil {
			return fmt.Errorf("%w: %s", ErrUnknownVehicle, vehicleID)
		}
		if vehicle.Archived() {
			return fmt.Errorf("%w: %s", ErrVehicleArchived, vehicle.DisplayName)
		}

		nextSeq := 1
		for _, a := range d.Assignments {
			if a.VehicleID == vehicle.ID && a.Open() && a.DeviceID != deviceID {
				return fmt.Errorf("%w: %s holds %q; unassign it first",
					ErrVehicleBusy, a.DeviceID, vehicle.DisplayName)
			}
			if a.DeviceID == deviceID && a.Seq >= nextSeq {
				nextSeq = a.Seq + 1
			}
		}

		now := r.now()
		for _, a := range d.Assignments {
			if a.DeviceID == deviceID && a.Open() {
				a.EndsAt = now
			}
		}

		if assignmentID == "" {
			id, err := NewID()
			if err != nil {
				return err
			}
			assignmentID = hex.EncodeToString(id[:])
		}
		created = &Assignment{
			ID:         assignmentID,
			DeviceID:   deviceID,
			VehicleID:  vehicle.ID,
			Seq:        nextSeq,
			StartsAt:   now,
			AssignedBy: assignedBy,
		}
		d.Assignments = append(d.Assignments, created)
		return nil
	})
	if err != nil {
		return nil, err
	}
	c := *created
	return &c, nil
}

// Unassign ends a device's open assignment, if it has one.
func (r *Registry) Unassign(deviceID string) error {
	deviceID = strings.ToLower(deviceID)
	return r.store.Update(func(d *document) error {
		for _, a := range d.Assignments {
			if a.DeviceID == deviceID && a.Open() {
				a.EndsAt = r.now()
			}
		}
		return nil
	})
}

// ActiveFor returns the device's open assignment, or nil when it has none.
func (r *Registry) ActiveFor(deviceID string) *Assignment {
	deviceID = strings.ToLower(deviceID)
	var out *Assignment
	r.store.View(func(d *document) {
		for _, a := range d.Assignments {
			if a.DeviceID == deviceID && a.Open() {
				c := *a
				out = &c
			}
		}
	})
	return out
}

// Assignments lists a device's assignments in order, oldest first. An empty
// deviceID lists everyone's.
func (r *Registry) Assignments(deviceID string) []*Assignment {
	deviceID = strings.ToLower(deviceID)
	var out []*Assignment
	r.store.View(func(d *document) {
		for _, a := range d.Assignments {
			if deviceID == "" || a.DeviceID == deviceID {
				c := *a
				out = append(out, &c)
			}
		}
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// CheckBundle decides whether a bundle's claimed vehicle and assignment are
// acceptable for a device, given the bundle's counter. It does not change
// anything; Observe records an accepted bundle.
func (r *Registry) CheckBundle(deviceID, vehicleID, assignmentID string, counter uint64) error {
	deviceID, vehicleID, assignmentID = strings.ToLower(deviceID), strings.ToLower(vehicleID), strings.ToLower(assignmentID)

	var verr error
	r.store.View(func(d *document) {
		var claimed *Assignment
		for _, a := range d.Assignments {
			if a.ID == assignmentID {
				claimed = a
			}
		}
		if claimed == nil {
			verr = fmt.Errorf("%w: %s", ErrAssignmentUnknown, assignmentID)
			return
		}
		if claimed.DeviceID != deviceID || claimed.VehicleID != vehicleID {
			verr = fmt.Errorf("%w: assignment %s fits device %s to vehicle %s, bundle says device %s, vehicle %s",
				ErrAssignmentMismatch, assignmentID, claimed.DeviceID, claimed.VehicleID, deviceID, vehicleID)
			return
		}

		for _, v := range d.Vehicles {
			if v.ID == claimed.VehicleID && v.Archived() {
				verr = fmt.Errorf("%w: %s", ErrVehicleArchived, v.DisplayName)
				return
			}
		}

		// Superseded: a newer assignment of this device has already been seen
		// at a counter below this bundle's.
		for _, a := range d.Assignments {
			if a.DeviceID == deviceID && a.Seq > claimed.Seq &&
				a.FirstCounter != 0 && counter > a.FirstCounter {
				verr = fmt.Errorf("%w: assignment #%d was in use at counter %d, this bundle is counter %d under #%d",
					ErrAssignmentSuperseded, a.Seq, a.FirstCounter, counter, claimed.Seq)
				return
			}
		}
	})
	return verr
}

// Observe records that a bundle with this counter was accepted under the
// assignment. It is what lets CheckBundle recognise a stale reuse later.
func (r *Registry) Observe(assignmentID string, counter uint64) error {
	assignmentID = strings.ToLower(assignmentID)
	return r.store.Update(func(d *document) error {
		for _, a := range d.Assignments {
			if a.ID != assignmentID {
				continue
			}
			if a.FirstCounter == 0 || counter < a.FirstCounter {
				a.FirstCounter = counter
			}
			if counter > a.LastCounter {
				a.LastCounter = counter
			}
			return nil
		}
		return fmt.Errorf("%w: %s", ErrAssignmentUnknown, assignmentID)
	})
}

// NewID returns a UUIDv7: 48 bits of millisecond time then random bits, so IDs
// sort by creation and are still unguessable.
func NewID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("generate id: %w", err)
	}
	ms := uint64(time.Now().UnixMilli())
	id[0], id[1], id[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
	id[3], id[4], id[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	id[6] = id[6]&0x0f | 0x70 // version 7
	id[8] = id[8]&0x3f | 0x80 // RFC 4122 variant
	return id, nil
}
