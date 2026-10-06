package buildinfo

import "testing"

func TestGetNeverReturnsEmpty(t *testing.T) {
	in := Get()
	if in.Version == "" || in.Commit == "" {
		t.Fatalf("empty identity: %+v", in)
	}
}

func TestLinkTimeValuesWin(t *testing.T) {
	Version, Commit = "v9.9.9", "abc123"
	defer func() { Version, Commit = "", "" }()
	if in := Get(); in.Version != "v9.9.9" || in.Commit != "abc123" {
		t.Fatalf("link-time values ignored: %+v", in)
	}
}
