package vehicles

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// A tune record marks the day a car's engine management changed. Boost, lambda and fuel
// trim are only comparable across a tune once the store knows where the tune falls, and a
// record is the owner's word for that: the dongle cannot see a flash.
//
// The date is a calendar day, not an instant. Owners know the day they picked the car up
// from the tuner, not the minute, and a trip is counted "after" when it starts on or after
// that day at 00:00 UTC. That puts a late-evening drive on the tune day on the "after"
// side in the Americas and a pre-dawn one on the "before" side in Asia; the tune record
// carries no time zone to do better, and a day either way never changes a median that
// holds weeks of driving.

var (
	// ErrUnknownTune means the vehicle has no tune with this ID.
	ErrUnknownTune = errors.New("tune record not found")
	// ErrBadTune means the date or note was refused.
	ErrBadTune = errors.New("invalid tune record")
)

const (
	// MaxTunesPerVehicle bounds a car's history: it is read on every health request.
	MaxTunesPerVehicle = 50
	// MaxTuneNote bounds the owner's note, in characters.
	MaxTuneNote = 500
	// TuneDateLayout is how a tune's date is written.
	TuneDateLayout = "2006-01-02"
)

// Tune is one tune record.
type Tune struct {
	ID        string    `json:"id"` // hex of a 16-byte UUIDv7
	VehicleID string    `json:"vehicle_id"`
	At        string    `json:"at"` // YYYY-MM-DD
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Time is the tune's date as an instant, 00:00 UTC.
func (t Tune) Time() time.Time {
	d, _ := time.Parse(TuneDateLayout, t.At)
	return d
}

func (r *Registry) checkTune(at, note string) (string, string, error) {
	at = strings.TrimSpace(at)
	day, err := time.Parse(TuneDateLayout, at)
	if err != nil {
		return "", "", fmt.Errorf("%w: the date must be YYYY-MM-DD", ErrBadTune)
	}
	// A day ahead is allowed so a clock a few hours off, or an owner in a time zone
	// ahead of UTC, can record today's tune.
	if day.After(r.now().Add(48 * time.Hour)) {
		return "", "", fmt.Errorf("%w: %s is in the future", ErrBadTune, at)
	}
	if day.Year() < 1990 {
		return "", "", fmt.Errorf("%w: %s predates any car this could describe", ErrBadTune, at)
	}
	note = strings.TrimSpace(note)
	if n := len([]rune(note)); n > MaxTuneNote {
		return "", "", fmt.Errorf("%w: the note is %d characters, the limit is %d", ErrBadTune, n, MaxTuneNote)
	}
	return at, note, nil
}

// AddTune records a tune for a vehicle. An archived vehicle takes none: it accepts no new
// facts, only keeps its history.
func (r *Registry) AddTune(vehicleID, at, note, by string) (*Tune, error) {
	at, note, err := r.checkTune(at, note)
	if err != nil {
		return nil, err
	}
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	var out Tune
	err = r.store.Update(func(d *document) error {
		v := find(d, vehicleID)
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUnknownVehicle, vehicleID)
		}
		if v.Archived() {
			return fmt.Errorf("%w: %s", ErrVehicleArchived, v.DisplayName)
		}
		if len(v.Tunes) >= MaxTunesPerVehicle {
			return fmt.Errorf("%w: a vehicle holds at most %d tune records", ErrBadTune, MaxTunesPerVehicle)
		}
		out = Tune{ID: hex.EncodeToString(id[:]), VehicleID: v.ID, At: at, Note: note,
			CreatedAt: r.now(), CreatedBy: by}
		v.Tunes = append(v.Tunes, out)
		sortTunes(v.Tunes)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateTune changes a tune's date and note. Who created it and when is kept.
func (r *Registry) UpdateTune(vehicleID, tuneID, at, note string) (*Tune, error) {
	at, note, err := r.checkTune(at, note)
	if err != nil {
		return nil, err
	}
	var out Tune
	err = r.store.Update(func(d *document) error {
		v := find(d, vehicleID)
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUnknownVehicle, vehicleID)
		}
		if v.Archived() {
			return fmt.Errorf("%w: %s", ErrVehicleArchived, v.DisplayName)
		}
		for i := range v.Tunes {
			if strings.EqualFold(v.Tunes[i].ID, tuneID) {
				v.Tunes[i].At, v.Tunes[i].Note = at, note
				out = v.Tunes[i]
				sortTunes(v.Tunes)
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrUnknownTune, tuneID)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTune removes a tune record. It changes no stored trip: the before and after
// comparison is recomputed from the records that remain.
func (r *Registry) DeleteTune(vehicleID, tuneID string) error {
	return r.store.Update(func(d *document) error {
		v := find(d, vehicleID)
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUnknownVehicle, vehicleID)
		}
		if v.Archived() {
			return fmt.Errorf("%w: %s", ErrVehicleArchived, v.DisplayName)
		}
		for i := range v.Tunes {
			if strings.EqualFold(v.Tunes[i].ID, tuneID) {
				v.Tunes = append(v.Tunes[:i:i], v.Tunes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrUnknownTune, tuneID)
	})
}

// Tunes lists a vehicle's tune records, oldest first.
func (r *Registry) Tunes(vehicleID string) ([]Tune, error) {
	v, err := r.Vehicle(vehicleID)
	if err != nil {
		return nil, err
	}
	return v.Tunes, nil
}

// AllTunes lists every tune record of every vehicle, for loading into the store.
func (r *Registry) AllTunes() []Tune {
	var out []Tune
	for _, v := range r.Vehicles() {
		out = append(out, v.Tunes...)
	}
	return out
}

func find(d *document, id string) *Vehicle {
	for _, v := range d.Vehicles {
		if strings.EqualFold(v.ID, id) {
			return v
		}
	}
	return nil
}

func sortTunes(t []Tune) {
	sort.SliceStable(t, func(i, j int) bool {
		if t[i].At != t[j].At {
			return t[i].At < t[j].At
		}
		return t[i].CreatedAt.Before(t[j].CreatedAt)
	})
}

// ReadTunes reads every tune record from a registry file without opening the registry: no
// key file is created and nothing is written, so a process that only analyses data (the
// store) can follow the registry safely. A missing file holds no tunes.
func ReadTunes(path string) ([]Tune, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read vehicles: %w", err)
	}
	var d document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse vehicles: %w", err)
	}
	var out []Tune
	for _, v := range d.Vehicles {
		for _, t := range v.Tunes {
			t.VehicleID = v.ID
			out = append(out, t)
		}
	}
	return out, nil
}
