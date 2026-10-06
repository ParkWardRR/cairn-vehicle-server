package decode_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/decode"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// decodeFor builds a bundle bound to vehicle and decodes it from a fresh CAS.
func decodeFor(t *testing.T, vehicle [16]byte, opts testbundle.Options) *decode.Result {
	t.Helper()
	opts.VehicleID = vehicle
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cas.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range b.Members() {
		if err := store.Put(sha256.Sum256(data), data); err != nil {
			t.Fatal(err)
		}
	}
	md := sha256.Sum256(b.ManifestBytes)
	if err := store.Put(md, b.ManifestBytes); err != nil {
		t.Fatal(err)
	}
	res, err := decode.New(store, testbundle.Keys()).Decode(context.Background(),
		decode.Input{ContentRoot: b.Manifest.ContentRoot, ManifestDigest: md})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func vehicle(b byte) [16]byte {
	var v [16]byte
	for i := range v {
		v[i] = b + byte(i)
	}
	return v
}

// Every decoded row must say which car it came from, and it must be the car the
// manifest names. A row without it is a row a per-vehicle store cannot keep
// apart from another engine's.
func TestEveryRowCarriesTheManifestVehicle(t *testing.T) {
	n20 := vehicle(0x70)
	opts := testbundle.Default()
	opts.GapAfter = 5
	res := decodeFor(t, n20, opts)

	if res.VehicleID != n20 {
		t.Fatalf("result vehicle = %x, want %x", res.VehicleID, n20)
	}
	check := func(kind string, i int, got [16]byte) {
		t.Helper()
		if got != n20 {
			t.Errorf("%s[%d] vehicle = %x, want %x", kind, i, got, n20)
		}
	}
	for i := range res.Positions {
		check("position", i, res.Positions[i].VehicleID)
	}
	for i := range res.IMU {
		check("imu", i, res.IMU[i].VehicleID)
	}
	for i := range res.OBD {
		check("obd", i, res.OBD[i].VehicleID)
	}
	for i := range res.Boost {
		check("boost", i, res.Boost[i].VehicleID)
	}
	for i := range res.Status {
		check("status", i, res.Status[i].VehicleID)
	}
	for i := range res.Transitions {
		check("transition", i, res.Transitions[i].VehicleID)
	}
	for i := range res.Gaps {
		check("gap", i, res.Gaps[i].VehicleID)
	}
	for i := range res.Events {
		check("event", i, res.Events[i].VehicleID)
	}
	if res.Trip == nil {
		t.Fatal("no trip derived")
	}
	check("trip", 0, res.Trip.VehicleID)

	// The fixture must actually exercise the row kinds, or the loop above
	// proves nothing.
	if len(res.Positions) == 0 || len(res.OBD) == 0 || len(res.Transitions) == 0 || len(res.Gaps) == 0 || len(res.Events) == 0 {
		t.Fatalf("fixture too thin: %d pos, %d obd, %d transitions, %d gaps, %d events",
			len(res.Positions), len(res.OBD), len(res.Transitions), len(res.Gaps), len(res.Events))
	}
}

// The vehicle is part of the output, so it is part of the digest: the same
// drive bound to another car is different output, and one row whose vehicle
// drifted from the rest must move the digest too.
func TestDigestCoversTheVehicle(t *testing.T) {
	a := decodeFor(t, vehicle(0x70), testbundle.Default())
	b := decodeFor(t, vehicle(0x90), testbundle.Default())
	if a.OutputDigest() == b.OutputDigest() {
		t.Fatal("two vehicles produced the same digest")
	}

	before := a.OutputDigest()
	a.OBD[len(a.OBD)-1].VehicleID = vehicle(0x90)
	if a.OutputDigest() == before {
		t.Fatal("a row re-labelled to another vehicle did not change the digest")
	}
}
