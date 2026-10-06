package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

type driveStyle struct {
	aAcc, aDec, aLat, speedF float64
}

var styles = map[string]driveStyle{
	"calm":     {aAcc: 1.3, aDec: 1.8, aLat: 1.7, speedF: 0.94},
	"brisk":    {aAcc: 1.9, aDec: 2.6, aLat: 2.3, speedF: 1.0},
	"spirited": {aAcc: 2.5, aDec: 3.3, aLat: 3.0, speedF: 1.06},
}

const ds = 5.0 // grid spacing, metres

// grid is a route resampled every ds metres.
type grid struct {
	n       int
	lat     []float64
	lon     []float64
	heading []float64 // radians, clockwise from north
	kappa   []float64 // signed curvature, 1/m, left turns positive
	vlim    []float64 // m/s
	alt     []float64 // metres
}

type stop struct {
	idx   int
	dwell float64
	aDec  float64
}

type zone struct{ i0, i1 int }

// tripOpts are the per-boot circumstances.
type tripOpts struct {
	start       time.Time // wall clock UTC at the moment the dongle woke
	coolStartC  float64   // coolant temperature at ignition
	ambientC    float64
	ttffS       float64 // seconds from GNSS power-up to first fix
	idleS       float64 // sitting still before moving off
	ltftBase    float64
	endsAtHome  bool
	origin      string
	sdFreeMiB   int
	deviceTempC float64
	gap         bool
}

type counts struct{ pos, imu, obd, boost, status, trans, gap uint32 }

type bundleInfo struct {
	root, bundleID, bootID string
	counts                 counts
	durationMS             int
	origin                 string
	startWall, endWall     time.Time
	endLat, endLon         float64
	sdFreeMiB              int
}

func hexOf(parts ...any) string {
	h := sha256.Sum256([]byte(fmt.Sprint(parts...)))
	return hex.EncodeToString(h[:])
}

func buildGrid(rt route, via []string, ripple float64, rng *rand.Rand) *grid {
	lat0 := rt.Coords[0][1]
	cosLat := math.Cos(lat0 * math.Pi / 180)
	toXY := func(c [2]float64) (float64, float64) {
		return (c[0] - rt.Coords[0][0]) * cosLat * 111320, (c[1] - lat0) * 110540
	}

	// Cumulative distance along the polyline.
	cum := make([]float64, len(rt.Coords))
	for i := 1; i < len(rt.Coords); i++ {
		x0, y0 := toXY(rt.Coords[i-1])
		x1, y1 := toXY(rt.Coords[i])
		cum[i] = cum[i-1] + math.Hypot(x1-x0, y1-y0)
	}
	total := cum[len(cum)-1]
	n := int(total/ds) + 1

	g := &grid{n: n}
	g.lat = make([]float64, n)
	g.lon = make([]float64, n)
	g.vlim = make([]float64, n)
	seg := 0
	for i := 0; i < n; i++ {
		d := float64(i) * ds
		for seg < len(cum)-2 && cum[seg+1] < d {
			seg++
		}
		span := cum[seg+1] - cum[seg]
		f := 0.0
		if span > 0 {
			f = (d - cum[seg]) / span
		}
		f = math.Max(0, math.Min(1, f))
		g.lon[i] = rt.Coords[seg][0] + f*(rt.Coords[seg+1][0]-rt.Coords[seg][0])
		g.lat[i] = rt.Coords[seg][1] + f*(rt.Coords[seg+1][1]-rt.Coords[seg][1])
		// OSRM's car profile is conservative on small roads; scale towards what
		// people actually drive, and never past 26 m/s.
		g.vlim[i] = math.Min(26, math.Max(6, rt.Speeds[seg]*1.3))
	}

	xy := func(i int) (float64, float64) {
		return (g.lon[i] - g.lon[0]) * cosLat * 111320, (g.lat[i] - g.lat[0]) * 110540
	}
	g.heading = make([]float64, n)
	for i := 0; i < n; i++ {
		a, b := max(0, i-2), min(n-1, i+2)
		x0, y0 := xy(a)
		x1, y1 := xy(b)
		g.heading[i] = math.Atan2(x1-x0, y1-y0)
	}
	g.kappa = make([]float64, n)
	for i := 0; i < n; i++ {
		a, b := max(0, i-4), min(n-1, i+4)
		if b == a {
			continue
		}
		dh := g.heading[b] - g.heading[a]
		for dh > math.Pi {
			dh -= 2 * math.Pi
		}
		for dh < -math.Pi {
			dh += 2 * math.Pi
		}
		// Heading grows clockwise, so a right turn has positive dh; flip so left
		// is positive.
		g.kappa[i] = -dh / (float64(b-a) * ds)
	}

	// Altitude: pin the via points, blend between them, then add the wobble of
	// a cliff road.
	type knot struct {
		idx int
		alt float64
	}
	var knots []knot
	for _, name := range via {
		p := places[name]
		best, bi := math.MaxFloat64, 0
		for i := 0; i < n; i++ {
			x, y := xy(i)
			px, py := (p.lon-g.lon[0])*cosLat*111320, (p.lat-g.lat[0])*110540
			if d := math.Hypot(x-px, y-py); d < best {
				best, bi = d, i
			}
		}
		knots = append(knots, knot{bi, p.altM})
	}
	knots[0].idx = 0
	knots[len(knots)-1].idx = n - 1
	for i := 1; i < len(knots); i++ { // keep the knots ordered along the route
		if knots[i].idx < knots[i-1].idx {
			knots[i].idx = knots[i-1].idx
		}
	}
	phase := rng.Float64() * 6
	g.alt = make([]float64, n)
	k := 0
	for i := 0; i < n; i++ {
		for k < len(knots)-2 && knots[k+1].idx < i {
			k++
		}
		a, b := knots[k], knots[k+1]
		f := 0.0
		if b.idx > a.idx {
			f = math.Max(0, math.Min(1, float64(i-a.idx)/float64(b.idx-a.idx)))
		}
		f = (1 - math.Cos(f*math.Pi)) / 2
		d := float64(i) * ds
		g.alt[i] = a.alt + f*(b.alt-a.alt) + 0.5*ripple*math.Sin(d/1300+phase) + 0.2*ripple*math.Sin(d/420+2*phase)
	}
	return g
}

func reverse(rt route) route {
	c := slices.Clone(rt.Coords)
	slices.Reverse(c)
	s := slices.Clone(rt.Speeds)
	slices.Reverse(s)
	return route{Coords: c, Speeds: s}
}

func aCap(v float64) float64 {
	return math.Max(2.2, 5.2*(1-v/58))
}

// profile is the speed the driver holds at every grid point: the lowest of the
// limit, what the corners allow and what the next stop allows, then smoothed
// so the car can actually accelerate to and brake from it.
func profile(g *grid, st driveStyle, stops []stop, zones []zone) []float64 {
	n := g.n
	v := make([]float64, n)
	inZone := make([]bool, n)
	for _, z := range zones {
		for i := z.i0; i <= z.i1 && i < n; i++ {
			inZone[i] = true
		}
	}
	for i := 0; i < n; i++ {
		lim := g.vlim[i] * st.speedF
		if inZone[i] {
			lim = math.Min(31, lim+8)
		}
		// Look a few metres either side so the car slows before a bend, not in it.
		var kmax float64
		for j := max(0, i-6); j <= min(n-1, i+6); j++ {
			kmax = math.Max(kmax, math.Abs(g.kappa[j]))
		}
		vc := 40.0
		if kmax > 1e-4 {
			vc = math.Sqrt(st.aLat / kmax)
		}
		v[i] = math.Min(lim, math.Max(4, vc))
	}
	v[0], v[n-1] = 0, 0

	for _, s := range stops {
		for i := 0; i <= s.idx; i++ {
			d := float64(s.idx-i) * ds
			v[i] = math.Min(v[i], math.Sqrt(2*s.aDec*d))
		}
		v[s.idx] = 0
	}
	for i := n - 2; i >= 0; i-- {
		v[i] = math.Min(v[i], math.Sqrt(v[i+1]*v[i+1]+2*st.aDec*ds))
	}
	for i := 1; i < n; i++ {
		a := st.aAcc
		if inZone[i] {
			a = aCap(v[i-1])
		}
		v[i] = math.Min(v[i], math.Sqrt(v[i-1]*v[i-1]+2*a*ds))
	}
	return v
}

func pickStops(g *grid, st driveStyle, rng *rand.Rand) []stop {
	var stops []stop
	i := 20
	for i < g.n-20 {
		if g.vlim[i] < 14 && g.vlim[min(g.n-1, i+30)] < 14 {
			i += int((250 + rng.Float64()*500) / ds)
			if i >= g.n-20 {
				break
			}
			dwell := 3 + rng.Float64()*4 // stop sign
			if rng.Float64() < 0.4 {
				dwell = 12 + rng.Float64()*33 // signal
			}
			stops = append(stops, stop{idx: i, dwell: dwell, aDec: st.aDec * (0.85 + rng.Float64()*0.5)})
			continue
		}
		i++
	}
	return stops
}

func pickZones(g *grid, st driveStyle, v0 []float64, name string, rng *rand.Rand) []zone {
	km := float64(g.n) * ds / 1000
	var want int
	switch name {
	case "spirited":
		want = min(4, int(math.Round(km/4)))
	case "brisk":
		want = min(2, int(math.Round(km/8)))
	}
	if want == 0 {
		return nil
	}
	var cands []int
	for i := 40; i < g.n-120; i++ {
		if v0[i] > 9 {
			continue
		}
		ok := true
		for j := i; j < i+80 && ok; j++ {
			if g.vlim[j]*st.speedF < 17 || math.Abs(g.kappa[j]) > 1.0/180 {
				ok = false
			}
		}
		if ok {
			cands = append(cands, i)
		}
	}
	rng.Shuffle(len(cands), func(a, b int) { cands[a], cands[b] = cands[b], cands[a] })
	var zones []zone
	for _, c := range cands {
		if len(zones) >= want {
			break
		}
		clash := false
		for _, z := range zones {
			if abs(c-z.i0) < 300 {
				clash = true
			}
		}
		if !clash {
			zones = append(zones, zone{c, c + 36})
		}
	}
	return zones
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

var gearK = func() [8]float64 {
	ratios := [8]float64{5.25, 3.29, 2.17, 1.68, 1.31, 1.0, 0.82, 0.64}
	var k [8]float64
	for i, r := range ratios {
		k[i] = 60 / 2.05 * 3.15 * r // rpm per m/s
	}
	return k
}()

func smoothstep(x float64) float64 {
	x = math.Max(0, math.Min(1, x))
	return x * x * (3 - 2*x)
}

func clamp(x, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, x)) }

func trimBase(rpm, load float64) float64 {
	b := 0.0
	switch {
	case load < 35:
		b += 2.4
	case load < 60:
		b -= 1.1
	default:
		b += 0.5
	}
	if rpm < 1200 {
		b += 0.9
	}
	if rpm > 3500 && load < 60 {
		b -= 0.8
	}
	return b
}

// simulate drives one boot along rt and appends its rows.
func simulate(apps tsdb.Appenders, rng *rand.Rand, rt route, t *template, style string, o tripOpts, boot string) (bundleInfo, error) {
	st := styles[style]
	via := t.via
	g := buildGrid(rt, via, t.ripple, rng)
	stops := pickStops(g, st, rng)
	v0 := profile(g, st, stops, nil)
	zones := pickZones(g, st, v0, style, rng)
	prof := profile(g, st, stops, zones)

	root := hexOf("root", boot)
	bundleID := hexOf("bundle", boot)[:32]
	var c counts
	var seq uint32
	next := func() uint32 { seq++; return seq }

	monoBoot := uint32(1800 + rng.IntN(1400))
	wall := func(mono uint32) time.Time {
		return o.start.Add(time.Duration(mono-monoBoot) * time.Millisecond)
	}
	monoAt := func(tsec float64) uint32 { return monoBoot + 2800 + uint32(math.Round(tsec*1000)) }

	// ---- position helper -------------------------------------------------
	canyon := 0.0
	emitPosition := func(tsec float64, s, v float64, haveFix bool) error {
		mono := monoAt(tsec)
		if !haveFix {
			sats := int16(rng.IntN(4))
			vis := int16(3 + rng.IntN(8))
			c.pos++
			return apps.Append("position", demoVehicleID, root, boot, mono, next(), wall(mono),
				0.0, 0.0, nil, nil, nil,
				uint8(0), sats, vis, nil, nil, nil, nil, uint8(1), uint16(0))
		}
		fi := s / ds
		i0 := int(fi)
		if i0 >= g.n-1 {
			i0 = g.n - 2
		}
		f := fi - float64(i0)
		lat := g.lat[i0] + f*(g.lat[i0+1]-g.lat[i0])
		lon := g.lon[i0] + f*(g.lon[i0+1]-g.lon[i0])
		alt := g.alt[i0] + f*(g.alt[i0+1]-g.alt[i0])
		// A metre or two of GNSS jitter.
		lat += rng.NormFloat64() * 1.0 / 110540
		lon += rng.NormFloat64() * 1.0 / (111320 * math.Cos(lat*math.Pi/180))
		canyon = clamp(canyon+rng.NormFloat64()*0.08-(canyon-0.1*(1+t.ripple/15))*0.04, 0, 1)
		sats := int16(math.Round(18 - 9*canyon + rng.NormFloat64()*1.2))
		sats = max(5, min(24, sats))
		hacc := 2.1 + 9*canyon*canyon + math.Abs(rng.NormFloat64())*0.6
		hd := math.Mod(g.heading[i0]*180/math.Pi+360, 360)
		spd := math.Max(0, v+rng.NormFloat64()*0.08)
		c.pos++
		return apps.Append("position", demoVehicleID, root, boot, mono, next(), wall(mono),
			lat, lon, alt+rng.NormFloat64()*0.12, spd, hd,
			uint8(3), sats, sats+int16(rng.IntN(6)+3), 0.8+canyon*1.4+rng.Float64()*0.3, hacc, hacc*1.6, int32(25+rng.IntN(40)),
			uint8(1), uint16(0))
	}

	// ---- engine state ----------------------------------------------------
	var (
		sPos      float64
		v, aF     float64
		gear      int
		gearCD    int
		mapKpa    = 35.0
		boostPsi  float64
		lam       = 1.0
		stft      = 0.0
		ltftS     = o.ltftBase
		thr       float64
		rpm       = 760.0
		holdLeft  = o.idleS
		stopPtr   int
		finished  bool
		finalIdle = 4 + rng.Float64()*8
	)
	peak := 17.0 + rng.NormFloat64()*0.9
	trimOff := rng.NormFloat64() * 0.5

	// IMU window accumulators.
	var winN int
	var px, py, pz, gyroPk, sumSq float64
	var flags uint8
	resetWin := func() { winN, px, py, pz, gyroPk, sumSq, flags = 0, 0, 0, 0, 0, 0, 0 }

	// Pre-roll: GNSS is powered before the OBD session is up.
	fixed := func(tsec float64) bool { return tsec >= o.ttffS-2.6 }
	for _, tp := range []float64{-2.5, -1.5, -0.5} {
		if err := emitPosition(tp, 0, 0, fixed(tp)); err != nil {
			return bundleInfo{}, err
		}
	}

	gapStart, gapLen := math.MaxFloat64, 0.0
	if o.gap {
		gapStart = 40 + rng.Float64()*120
		gapLen = 1.5 + rng.Float64()*2.5
	}
	var gapDone bool

	dt := 0.1
	var lastMono uint32
	var statusDue = 0.0
	var endLat, endLon float64
	var simT float64

	for tick := 0; !finished; tick++ {
		simT = float64(tick) * dt

		// Speed target from the profile, or hold.
		prevV := v
		if holdLeft > 0 {
			v = 0
			holdLeft -= dt
		} else {
			fi := sPos / ds
			i0 := min(int(fi), g.n-2)
			f := fi - float64(i0)
			vp := prof[i0] + f*(prof[i0+1]-prof[i0])
			nearStop := false
			if stopPtr < len(stops) {
				if float64(stops[stopPtr].idx)*ds-sPos < 3 {
					nearStop = true
				}
			}
			if !nearStop {
				vp = math.Max(vp, 0.5)
			}
			v = vp
			sPos += v * dt
			if stopPtr < len(stops) && sPos >= float64(stops[stopPtr].idx)*ds-0.4 {
				sPos = float64(stops[stopPtr].idx) * ds
				holdLeft = stops[stopPtr].dwell
				stopPtr++
				v = 0
			}
			if sPos >= float64(g.n-1)*ds-0.4 {
				sPos = float64(g.n-1) * ds
				holdLeft = finalIdle
				v = 0
				finished = true
			}
		}
		aRaw := (v - prevV) / dt
		aF = 0.7*aF + 0.3*aRaw

		fi := math.Min(sPos/ds, float64(g.n-1)-1e-6)
		i0 := int(fi)
		kappa := g.kappa[i0]
		alt := g.alt[i0]
		slope := 0.0
		if i0+1 < g.n && v > 0.5 {
			slope = (g.alt[i0+1] - g.alt[i0]) / ds
		}

		// Throttle from the force the car needs.
		aReq := aF + 0.12 + 0.0004*v*v + 9.81*slope
		switch {
		case aReq <= 0.02:
			thr = 0
		default:
			thr = clamp(6+94*aReq/aCap(v), 2, 100)
		}
		if v < 0.3 {
			thr = 0
		}
		thr = clamp(thr+rng.NormFloat64()*1.2, 0, 100)

		// Gearbox.
		if gearCD > 0 {
			gearCD--
		}
		if v < 1.2 {
			gear = 0
		} else if gearCD == 0 {
			r := gearK[gear] * v
			up := 1800 + math.Max(0, thr-35)*72
			dn := 1150 + thr*12
			if gear < 7 && r > up && gearK[gear+1]*v >= 1000+thr*28 {
				gear++
				gearCD = 8
			} else if gear > 0 && r < dn {
				for gear > 0 && gearK[gear]*v < 1400+thr*20 {
					gear--
				}
				gearCD = 8
			}
		}
		rpm = gearK[gear] * v
		if gear == 0 && v < 4.5 && thr > 15 {
			rpm = math.Max(rpm, 1500+thr*28)
		}
		rpm = clamp(math.Max(rpm, 740+rng.NormFloat64()*12), 700, 6900)

		// Air path.
		ambient := o.ambientC - 0.004*(alt-30)
		baro := 101.3*math.Exp(-alt/8400) + 0.4*math.Sin(simT/700)
		natural := 35 + 0.9*thr
		if thr < 4 && v > 2 {
			natural = 27 + rng.NormFloat64()*1.5
		}
		blend := clamp((thr-65)/25, 0, 1)
		psiT := peak * smoothstep((rpm-1700)/1300) * (1 - 0.35*clamp((rpm-5200)/1800, 0, 1)) * blend
		mapT := math.Min(natural, baro-2) + psiT*6.895
		tau := 0.25
		if mapT > mapKpa {
			tau = 0.5
		}
		mapKpa += (mapT - mapKpa) * (1 - math.Exp(-dt/tau))
		boostPsi = (mapKpa - baro) / 6.895

		load := clamp(100*mapKpa/baro*0.8, 14, 100)
		openLoop := thr > 85 && boostPsi > 2
		lamT := 1.0
		if openLoop {
			lamT = 0.92 - 0.0045*boostPsi
		}
		lam += (lamT - lam) * 0.4
		lam += rng.NormFloat64() * 0.004
		if openLoop {
			stft *= 0.5
		} else {
			stft += 0.12*(trimBase(rpm, load)*0.6+trimOff-stft) + rng.NormFloat64()*0.4
		}
		stft = clamp(stft, -9, 9)
		ltftRaw := o.ltftBase + trimBase(rpm, load)*0.7 + 0.6*math.Sin(simT/300)
		ltftS += 0.08 * (ltftRaw - ltftS)
		ltft := math.Round(ltftS)

		maf := rpm / 120 * 2.0 * 1.2 * (mapKpa / 101.3) * 0.85 * 100 // cg/s
		coolant := 90 - (90-o.coolStartC)*math.Exp(-simT/270) + 0.03*thr + rng.NormFloat64()*0.3
		coolant = clamp(coolant, 20, 99)
		intake := ambient + 6 + 10*(1-math.Exp(-simT/500)) + 0.45*math.Max(boostPsi, 0)
		timing := clamp(36-thr*0.12-math.Max(boostPsi, 0)*0.9+rng.NormFloat64()*0.8, 4, 40)
		fuelP := clamp(5200+thr*70+math.Max(0, rpm-1500)*0.9+rng.NormFloat64()*40, 4000, 13500)

		// IMU, accumulated at 10 Hz and summarised each 0.5 s.
		ax := aF*101.97 + rng.NormFloat64()*(8+rpm/180)
		ay := v * v * kappa * 101.97
		ay += rng.NormFloat64() * 9
		dz := rng.NormFloat64() * (22 + 4*v)
		if v > 5 && rng.Float64() < 0.00015 {
			dz += (300 + rng.Float64()*600) * float64(1-2*rng.IntN(2))
		}
		az := 1000 + dz
		yaw := v*kappa*180/math.Pi + rng.NormFloat64()*0.8
		if math.Abs(ax) > math.Abs(px) {
			px = ax
		}
		if math.Abs(ay) > math.Abs(py) {
			py = ay
		}
		if math.Abs(az-1000) > math.Abs(pz-1000) {
			pz = az
		}
		gyroPk = math.Max(gyroPk, math.Abs(yaw))
		sumSq += ax*ax + ay*ay + dz*dz
		winN++
		if aF < -3.85 {
			flags |= 2
		}
		if math.Abs(ay) > 430 {
			flags |= 4
		}
		if math.Abs(dz) > 650 {
			flags |= 8
		}

		// ---- emit on the 0.5 s boundary ---------------------------------
		if tick%5 == 4 {
			tsec := simT
			inGap := tsec >= gapStart && tsec < gapStart+gapLen
			if inGap && !gapDone {
				gapDone = true
				c.gap++
				if err := apps.Append("gap", demoVehicleID, root, boot, next(), wall(monoAt(tsec)), uint32(gapLen*1000), uint16(gapLen*4), uint8(2)); err != nil {
					return bundleInfo{}, err
				}
			}
			if !inGap {
				bm := monoAt(tsec) - 160
				ambC := int8(math.Round(ambient))
				answered := uint32(0x1FFF)
				perr := uint8(0)
				if rng.Float64() < 0.004 {
					answered = 0x1FFB
					perr = 1
				}
				stftOut := int8(math.Round(stft))
				c.boost++
				if err := apps.Append("boost", demoVehicleID, root, boot, bm, next(), wall(bm),
					uint16(math.Round(mapKpa)), uint8(math.Round(baro)), uint16(math.Round(maf)), uint16(math.Round(lam*10000)),
					uint16(load*100), ambC, stftOut, int8(ltft),
					// tank level: about 1 % per 6 km for a 52 L tank at ~9 L/100 km
					uint8(math.Max(8, 74-sPos/1000/5.8)),
					(math.Round(mapKpa)-math.Round(baro))/6.895, lam,
					uint32(0x1FFF), answered, uint16(495+rng.IntN(20))); err != nil {
					return bundleInfo{}, err
				}
				om := monoAt(tsec)
				kph := v*3.6*1.007 + rng.NormFloat64()*0.5
				if v < 0.3 {
					kph = 0
				}
				c.obd++
				if err := apps.Append("obd", demoVehicleID, root, boot, om, next(), wall(om),
					int16(math.Max(0, math.Round(kph))), int16(math.Round(rpm)), int16(math.Round(thr)), int16(math.Round(load)),
					int16(math.Round(coolant)), int16(math.Round(intake)),
					int32(math.Round(fuelP)), int16(math.Round(timing)),
					perr, uint32(0x1FFF), answered, int32(495+rng.IntN(20)), uint16(0)); err != nil {
					return bundleInfo{}, err
				}
				lastMono = om
			}

			// IMU summary.
			im := monoAt(tsec) + 40
			rms := math.Sqrt(sumSq / float64(winN))
			c.imu++
			if err := apps.Append("imu", demoVehicleID, root, boot, im, next(), wall(im),
				uint16(500), uint16(math.Min(rms, 60000)),
				int16(clamp(px, -32000, 32000)), int16(clamp(py, -32000, 32000)), int16(clamp(pz, -32000, 32000)),
				math.Round(gyroPk*10)/10, uint16(math.Min(rms*rms/100, 60000)), uint16(50),
				flags, uint16(0)); err != nil {
				return bundleInfo{}, err
			}
			resetWin()

			// GNSS at 1 Hz on the odd half-seconds.
			if (tick/5)%2 == 1 {
				if err := emitPosition(tsec+0.3, sPos, v, fixed(tsec+0.3)); err != nil {
					return bundleInfo{}, err
				}
			}

			// Status once a minute, and once at the start.
			if tsec >= statusDue {
				statusDue = tsec + 60
				sm := monoAt(tsec) + 80
				c.status++
				soak := o.deviceTempC + 14*(1-math.Exp(-tsec/900))
				if err := apps.Append("status", demoVehicleID, root, boot, sm, next(), wall(sm),
					int32(3990-int(tsec/20)+rng.IntN(25)), int32(0), int32(o.sdFreeMiB), int16(math.Round(soak+rng.NormFloat64()*0.4)),
					nil, nil, nil, uint8(0), uint8(0)); err != nil {
					return bundleInfo{}, err
				}
			}
		}
		endLat, endLon = g.lat[i0], g.lon[i0]
	}

	// Final status: on the way out the dongle sees the home network.
	endMono := monoAt(simT) + 120
	var rssi any
	if o.endsAtHome {
		rssi = int16(-52 - rng.IntN(12))
	}
	c.status++
	if err := apps.Append("status", demoVehicleID, root, boot, endMono, next(), wall(endMono),
		int32(3960+rng.IntN(20)), int32(0), int32(o.sdFreeMiB), int16(math.Round(o.deviceTempC+14+rng.NormFloat64()*0.5)),
		rssi, nil, nil, uint8(0), uint8(0)); err != nil {
		return bundleInfo{}, err
	}

	// Lifecycle: wake, capture, seal, and (at home) offer to the server, then sleep.
	type lifecycle struct {
		mono                   uint32
		region, from, to, trig uint8
		reason                 uint8
		start, stop            float64
		wake                   uint32
	}
	trans := []lifecycle{
		{monoBoot + 30, 4, 1, 0, 4, 1 + uint8(rng.IntN(2)), 0, 0, uint32(rng.IntN(2)*2 + 2)},
		{monoAt(0) - 200, 1, 0, 1, 1, 1, 8.4 + rng.Float64()*1.2, 0.2, 0},
		{endMono + 2000, 1, 1, 0, 2, 2, 0.3, 9.1 + rng.Float64(), 0},
		{endMono + 2600, 2, 1, 2, 3, 0, 0, 0, 0},
	}
	if o.endsAtHome {
		trans = append(trans, lifecycle{endMono + 9000, 3, 0, 1, 5, 0, 0, 0, 0})
	}
	trans = append(trans, lifecycle{endMono + 62000, 4, 0, 1, 4, 0, 0, 0, 0})
	for _, tr := range trans {
		c.trans++
		if err := apps.Append("transition", demoVehicleID, root, boot, tr.mono, next(), wall(tr.mono),
			tr.region, tr.from, tr.to, tr.trig, tr.reason, uint8(3), tr.start, tr.stop, tr.wake); err != nil {
			return bundleInfo{}, err
		}
	}

	endWall := wall(lastMono)
	return bundleInfo{
		root: root, bundleID: bundleID, bootID: boot, counts: c,
		durationMS: int(lastMono - monoBoot), origin: o.origin,
		startWall: o.start, endWall: endWall, endLat: endLat, endLon: endLon,
		sdFreeMiB: o.sdFreeMiB,
	}, nil
}
