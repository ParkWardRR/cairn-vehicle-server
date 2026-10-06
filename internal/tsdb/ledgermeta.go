package tsdb

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
)

// ledgerMeta reads how each committed bundle arrived from the server's lifecycle ledger.
//
// Path and received_at come from the bundle's committed entry. duration_ms is the time from
// the first offer to that commit: for a session that was cut off and resumed it includes the
// pauses, which is the number the owner experiences ("how long until my trip showed up")
// and not the radio time. A bundle with a commit but no offer (the ledger began after the
// offer) has a size and a time but no duration.
//
// A ledger that does not exist yet is an empty answer, not an error: a server that has
// committed nothing has nothing to report.
func ledgerMeta(dir string) (map[string]BundleMeta, []string, error) {
	out := map[string]BundleMeta{}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return out, nil, nil
	}
	book, err := ledger.Open(dir)
	if err != nil {
		return out, nil, err
	}
	defer book.Close()
	entries, err := book.Read()
	var notes []string
	if err != nil {
		// Read returns what it parsed before the damaged line; use it and say so.
		notes = append(notes, fmt.Sprintf("ledger is damaged after %d entries: %v", len(entries), err))
	}

	firstOffer := map[string]int64{}
	offerPath := map[string]string{}
	for _, e := range entries {
		if e.ContentRoot == "" {
			continue
		}
		switch e.Event {
		case ledger.EventOffered:
			if _, seen := firstOffer[e.ContentRoot]; !seen {
				firstOffer[e.ContentRoot] = e.UTCMS
				offerPath[e.ContentRoot] = e.Path
			}
		case ledger.EventCommitted:
			if _, done := out[e.ContentRoot]; done {
				continue // the first commit is the one that stored it
			}
			m := BundleMeta{Path: e.Path, ReceivedAt: time.UnixMilli(e.UTCMS).UTC()}
			if e.Bytes > 0 {
				m.SizeBytes = uint64(e.Bytes)
			}
			if m.Path == "" {
				m.Path = offerPath[e.ContentRoot]
			}
			if start, ok := firstOffer[e.ContentRoot]; ok && e.UTCMS >= start {
				d := e.UTCMS - start
				if d > int64(^uint32(0)) {
					d = int64(^uint32(0))
				}
				m.DurationMS = uint32(d)
			}
			out[e.ContentRoot] = m
		}
	}
	return out, notes, nil
}
