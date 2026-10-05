// Package counters is the server's memory of which bundle counters each device
// has used, and for what.
//
// Every sealed bundle carries a counter that the device increments in its own
// non-volatile storage — deliberately not on the SD card — and signs into the
// manifest. That makes the card replaceable without making history rewritable:
//
//   - A bundle uploaded twice, or an old card image restored, presents a
//     (counter, content_root) pair the server has already seen. That is a
//     duplicate, and is answered with the original receipt, as ever.
//   - A bundle presenting a counter the server has already seen *bound to
//     different content* is not a duplicate. A genuine device never seals two
//     different bundles with one counter, so this is a forgery, a cloned
//     device, or a reflashed unit whose counter went backwards — and in every
//     case it must be quarantined rather than ingested.
//   - A counter that jumps ahead leaves a hole. Holes are legitimate while a
//     device is still working through a backlog, so they are reported, not
//     refused: the useful question is "which bundles never arrived", and this
//     package can answer it.
//
// The counter is per device and survives re-keying. A device whose storage key
// is rotated is told the current high-water mark at enrolment and resumes above
// it, so a rotation cannot be used to reopen counter values already spent.
package counters

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ParkWardRR/Cairn/server/internal/jsonstore"
)

// Verdict is the outcome of checking a (counter, content_root) pair.
type Verdict int

const (
	// New means the counter has not been used.
	New Verdict = iota
	// Duplicate means the counter was already used for exactly this content.
	Duplicate
	// Conflict means the counter was already used for different content.
	Conflict
)

func (v Verdict) String() string {
	switch v {
	case New:
		return "new"
	case Duplicate:
		return "duplicate"
	case Conflict:
		return "conflict"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// ErrZeroCounter means a bundle claimed counter 0. Counters start at 1, so zero
// is what an uninitialised or zeroed field looks like.
var ErrZeroCounter = errors.New("bundle counter is zero")

// ErrCounterConflict means a counter was reused for different content.
var ErrCounterConflict = errors.New("bundle counter already used for different content")

type deviceState struct {
	HighWater uint64 `json:"high_water"`
	// Floor is the lowest counter this device is expected to have used. It is
	// raised when a device is re-enrolled above an earlier high-water mark, so
	// the counters below it are not reported as missing forever.
	Floor uint64 `json:"floor,omitempty"`
	// Seen maps a counter (decimal string, JSON object keys being strings) to
	// the content root it was bound to.
	Seen map[string]string `json:"seen"`
}

type document struct {
	Devices map[string]*deviceState `json:"devices"`
}

// Guard tracks counters for every device.
type Guard struct {
	store *jsonstore.Store[document]
}

// Open loads the guard state at path.
func Open(path string) (*Guard, error) {
	store, err := jsonstore.Open(path, func() document {
		return document{Devices: map[string]*deviceState{}}
	})
	if err != nil {
		return nil, err
	}
	return &Guard{store: store}, nil
}

// Check classifies a pair without recording it. gap is how many counters the
// bundle skips past the current high-water mark (0 when it is the next one or
// below it).
func (g *Guard) Check(deviceID string, counter uint64, contentRoot string) (v Verdict, gap uint64, err error) {
	if counter == 0 {
		return Conflict, 0, ErrZeroCounter
	}
	deviceID, contentRoot = strings.ToLower(deviceID), strings.ToLower(contentRoot)

	g.store.View(func(d *document) {
		st := d.Devices[deviceID]
		if st == nil {
			v = New
			if counter > 1 {
				gap = counter - 1
			}
			return
		}
		if prev, ok := st.Seen[strconv.FormatUint(counter, 10)]; ok {
			if prev == contentRoot {
				v = Duplicate
			} else {
				v, err = Conflict, fmt.Errorf("%w: counter %d was bound to %s, now %s",
					ErrCounterConflict, counter, short(prev), short(contentRoot))
			}
			return
		}
		v = New
		if counter > st.HighWater+1 {
			gap = counter - st.HighWater - 1
		}
	})
	return v, gap, err
}

// Record binds a counter to content. Recording the same pair twice is harmless;
// binding a counter to different content is refused here too, so a race between
// two offers cannot both succeed.
func (g *Guard) Record(deviceID string, counter uint64, contentRoot string) error {
	if counter == 0 {
		return ErrZeroCounter
	}
	deviceID, contentRoot = strings.ToLower(deviceID), strings.ToLower(contentRoot)

	return g.store.Update(func(d *document) error {
		st := d.Devices[deviceID]
		if st == nil {
			st = &deviceState{Seen: map[string]string{}}
			d.Devices[deviceID] = st
		}
		key := strconv.FormatUint(counter, 10)
		if prev, ok := st.Seen[key]; ok {
			if prev == contentRoot {
				return nil
			}
			return fmt.Errorf("%w: counter %d was bound to %s, now %s",
				ErrCounterConflict, counter, short(prev), short(contentRoot))
		}
		st.Seen[key] = contentRoot
		if counter > st.HighWater {
			st.HighWater = counter
		}
		return nil
	})
}

// HighWater returns the highest counter accepted for a device (0 if none).
func (g *Guard) HighWater(deviceID string) uint64 {
	deviceID = strings.ToLower(deviceID)
	var hw uint64
	g.store.View(func(d *document) {
		if st := d.Devices[deviceID]; st != nil {
			hw = st.HighWater
		}
	})
	return hw
}

// Missing lists counters at or below the high-water mark that were never
// accepted. A non-empty result means bundles were sealed that the server has
// not received — still on the card, lost, or deleted.
func (g *Guard) Missing(deviceID string) []uint64 {
	deviceID = strings.ToLower(deviceID)
	var out []uint64
	g.store.View(func(d *document) {
		st := d.Devices[deviceID]
		if st == nil {
			return
		}
		start := uint64(1)
		if st.Floor > start {
			start = st.Floor
		}
		for c := start; c <= st.HighWater; c++ {
			if _, ok := st.Seen[strconv.FormatUint(c, 10)]; !ok {
				out = append(out, c)
			}
		}
	})
	return out
}

// Resume returns the counter a re-enrolled device must start above, and
// records it as the new floor. The device initialises its own counter to
// max(its stored value, this), which is what stops a reflashed unit from
// reusing spent values.
func (g *Guard) Resume(deviceID string) (uint64, error) {
	deviceID = strings.ToLower(deviceID)
	var hw uint64
	err := g.store.Update(func(d *document) error {
		st := d.Devices[deviceID]
		if st == nil {
			return nil
		}
		hw = st.HighWater
		st.Floor = hw + 1
		return nil
	})
	return hw, err
}

// Devices lists the devices the guard knows, sorted.
func (g *Guard) Devices() []string {
	var out []string
	g.store.View(func(d *document) {
		for id := range d.Devices {
			out = append(out, id)
		}
	})
	sort.Strings(out)
	return out
}

func short(hex string) string {
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}
