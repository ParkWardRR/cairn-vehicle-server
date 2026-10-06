package testbundle

import (
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// Registries is the v3 binding state intake requires, pre-loaded so that
// bundles built with the default options are acceptable: the conventional
// synthetic vehicle exists, the synthetic device is assigned to it, and the
// default storage root is escrowed.
type Registries struct {
	Vehicles *vehicles.Registry
	Counters *counters.Guard
	Keys     *keystore.Store
}

// OpenRegistries creates the registries under dir and registers the synthetic
// device's vehicle, assignment and storage root. Calling it again over the same
// directory reuses what is there, so a simulated restart works.
func OpenRegistries(dir string) (*Registries, error) {
	vr, err := vehicles.Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "keys", "vehicles.key"))
	if err != nil {
		return nil, fmt.Errorf("vehicles: %w", err)
	}
	guard, err := counters.Open(filepath.Join(dir, "counters.json"))
	if err != nil {
		return nil, fmt.Errorf("counters: %w", err)
	}
	ks, err := keystore.Open(filepath.Join(dir, "keystore.json"), filepath.Join(dir, "keys", "keystore.master"))
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}

	deviceID, vehicleID, assignmentID := DeviceID(), VehicleID(), AssignmentID()
	deviceHex := hex.EncodeToString(deviceID[:])
	vehicleHex := hex.EncodeToString(vehicleID[:])

	if _, err := vr.Vehicle(vehicleHex); err != nil {
		if _, err := vr.CreateVehicle(vehicles.NewVehicleSpec{ID: vehicleHex, DisplayName: "test car"}); err != nil {
			return nil, err
		}
		if _, err := vr.AssignWithID(hex.EncodeToString(assignmentID[:]), deviceHex, vehicleHex, "test"); err != nil {
			return nil, err
		}
		if err := ks.Put(deviceHex, DefaultKeyVersion, RootKey()); err != nil {
			return nil, err
		}
	}
	return &Registries{Vehicles: vr, Counters: guard, Keys: ks}, nil
}
