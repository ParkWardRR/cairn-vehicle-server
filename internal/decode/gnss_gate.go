package decode

const (
	// maxFixSpeedMPS is the fastest speed a receiver may report before the fix
	// is treated as a glitch (~110 mph). Across the recorded trips the 99.9th
	// percentile is ~35 m/s; values near 65 m/s came from weak 4-6 satellite
	// fixes teleporting the position.
	maxFixSpeedMPS = 50.0

	// maxImpliedSpeedMPS bounds the speed implied by moving between two
	// consecutive accepted fixes. A reported speed can look sane while the
	// position itself has jumped, so this checks the positions directly.
	maxImpliedSpeedMPS = 40.0

	// jumpSlackM is added to the allowed distance so ordinary receiver jitter
	// on closely spaced fixes is never mistaken for a jump.
	jumpSlackM = 50.0

	// maxConsecutiveRejects bounds how long the gate may keep rejecting. Past
	// it, the next fix is accepted and becomes the new reference, so a bad
	// reference fix (or a real long displacement, e.g. a ferry or a tow) cannot
	// make the gate discard the rest of the trip.
	maxConsecutiveRejects = 5
)

// gateJumps drops position fixes that are kinematically impossible given the
// last accepted fix. positions must be ordered by seq, which is also time
// order within a boot. A recorded GNSS gap between two fixes explains any
// displacement across it (the receiver lost the sky and the vehicle moved on),
// so the gate does not judge fixes across one. It returns the surviving
// fixes and how many were dropped.
//
// The gate is deterministic: it depends only on the ordered input, so
// re-decoding the same bundle yields the same output digest.
func gateJumps(positions []Position, gaps []Gap) ([]Position, int) {
	if len(positions) < 2 {
		return positions, 0
	}

	kept := make([]Position, 0, len(positions))
	kept = append(kept, positions[0])
	rejects := 0

	for i := 1; i < len(positions); i++ {
		cur := positions[i]
		prev := kept[len(kept)-1]

		dt := float64(int64(cur.MonotonicMS)-int64(prev.MonotonicMS)) / 1000.0
		if dt < 1 {
			dt = 1
		}
		dist := haversineM(prev.Latitude, prev.Longitude, cur.Latitude, cur.Longitude)
		acrossGap := gapBetween(gaps, prev.Seq, cur.Seq)

		if !acrossGap && dist > jumpSlackM+maxImpliedSpeedMPS*dt && rejects < maxConsecutiveRejects {
			rejects++
			continue
		}
		rejects = 0
		kept = append(kept, cur)
	}

	return kept, len(positions) - len(kept)
}

// gapBetween reports whether a recorded gap falls between two sequence numbers.
func gapBetween(gaps []Gap, fromSeq, toSeq uint32) bool {
	for _, g := range gaps {
		if g.Seq > fromSeq && g.Seq < toSeq {
			return true
		}
	}
	return false
}
