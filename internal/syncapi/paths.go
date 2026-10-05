package syncapi

import "path/filepath"

// Paths is where the app API keeps its state under the server's data
// directory. It is one definition shared by the server and cairn-admin, because
// the two are separate processes that must agree on the files: an administrator
// who creates a vehicle or revokes a client from the command line is editing
// exactly what the running server reads.
type Paths struct {
	Vehicles   string // vehicle and assignment registry
	VehicleKey string // key sealing VINs
	Clients    string // enrolled app clients and invitations
	SyncDir    string // sync log segments and client acknowledgements
	AuditDir   string // daily audit files
	InstanceID string // stable server instance identifier
}

// DataPaths derives every path from the data directory.
func DataPaths(dataDir string) Paths {
	return Paths{
		Vehicles:   filepath.Join(dataDir, "vehicles.json"),
		VehicleKey: filepath.Join(dataDir, "keys", "vehicles.key"),
		Clients:    filepath.Join(dataDir, "clients.json"),
		SyncDir:    filepath.Join(dataDir, "sync"),
		AuditDir:   filepath.Join(dataDir, "audit"),
		InstanceID: filepath.Join(dataDir, "instance.id"),
	}
}
