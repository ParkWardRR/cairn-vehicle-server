package decode

import (
	"testing"

	"github.com/ParkWardRR/Cairn/server/format"
)

// The format package documents that every "unavailable" sentinel is "surfaced
// as a nil pointer rather than a zero value", because "collapsing them
// fabricates data". newStatus violated that for DEVICE_HEALTH: it wrapped every
// field in a pointer unconditionally, so a parked device with no ECU answering
// decoded to a supply of 65535 mV and a temperature of -128 C.
//
// Those are not harmless. They reach the database and the web UI looking like
// measurements, and internal/power derives a battery drain rate from the
// voltage series — fed 65535 mV it reports a discharge that never happened.
func TestHealthSentinelsDecodeToNil(t *testing.T) {
	// Every field at its unavailable sentinel, which is what the firmware
	// writes when the ECU is silent and no supply reading is possible.
	h := format.DeviceHealth{
		BatteryMV:     0xFFFF,
		SDWriteErrors: 0xFFFF,
		SDFreeMiB:     0xFFFF,
		DeviceTempC:   -0x80,
		RSSIdBm:       -0x80,
		ExtSensor1:    0xFFFF,
		ExtSensor2:    0xFFFF,
		HealthState:   0x1F,
		RebootCount:   7,
	}

	mf := &format.Manifest{UTCBasisMS: 1700000000000}
	st := newStatus(mf, &format.Frame{Seq: 3, MonotonicMS: 1000}, &h)

	if st.BatteryMV != nil {
		t.Errorf("BatteryMV = %d, want nil: 65535 reads as a supply voltage",
			*st.BatteryMV)
	}
	if st.DeviceTempC != nil {
		t.Errorf("DeviceTempC = %d, want nil: -128 reads as a temperature",
			*st.DeviceTempC)
	}
	if st.RSSIdBm != nil {
		t.Errorf("RSSIdBm = %d, want nil", *st.RSSIdBm)
	}
	if st.SDWriteErrors != nil {
		t.Errorf("SDWriteErrors = %d, want nil", *st.SDWriteErrors)
	}
	if st.SDFreeMiB != nil {
		t.Errorf("SDFreeMiB = %d, want nil", *st.SDFreeMiB)
	}
	if st.ExtSensor1 != nil || st.ExtSensor2 != nil {
		t.Error("ExtSensor fields at the sentinel did not decode to nil")
	}

	// Non-pointer fields carry no sentinel and must still arrive.
	if st.HealthState != 0x1F {
		t.Errorf("HealthState = %#x, want 0x1f", st.HealthState)
	}
	if st.RebootCount != 7 {
		t.Errorf("RebootCount = %d, want 7", st.RebootCount)
	}
}

// Real readings must survive, including the legitimate zeroes that the sentinel
// handling must not be confused with. Zero write errors is a fact.
func TestHealthRealValuesDecodeThrough(t *testing.T) {
	h := format.DeviceHealth{
		BatteryMV:     12450,
		SDWriteErrors: 0,
		SDFreeMiB:     15174,
		DeviceTempC:   21,
		RSSIdBm:       -67,
	}

	mf := &format.Manifest{UTCBasisMS: 1700000000000}
	st := newStatus(mf, &format.Frame{Seq: 1, MonotonicMS: 500}, &h)

	if st.BatteryMV == nil || *st.BatteryMV != 12450 {
		t.Error("a real supply reading did not decode through")
	}
	if st.SDWriteErrors == nil || *st.SDWriteErrors != 0 {
		t.Error("zero write errors is a measurement and must not decode to nil")
	}
	if st.DeviceTempC == nil || *st.DeviceTempC != 21 {
		t.Error("a real temperature did not decode through")
	}
	if st.RSSIdBm == nil || *st.RSSIdBm != -67 {
		t.Error("a real RSSI did not decode through")
	}
}
