package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

func TestHealthzReportsBuildAndStoreContract(t *testing.T) {
	s := buildTestServer(t)
	rec := httptest.NewRecorder()
	s.health(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Status        string `json:"status"`
		StoreContract string `json:"store_contract"`
		Build         struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		} `json:"build"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("healthz is not JSON: %v\n%s", err, rec.Body)
	}
	if got.Status != "ok" || got.StoreContract != tsdb.StoreContract {
		t.Fatalf("healthz: %+v", got)
	}
	if got.Build.Version == "" || got.Build.Commit == "" {
		t.Fatalf("healthz build identity is empty: %+v", got.Build)
	}
}

func TestCapabilitiesListsTheServingStore(t *testing.T) {
	s := buildTestServer(t)
	rec := httptest.NewRecorder()
	s.capabilities(rec, httptest.NewRequest("GET", "/capabilities", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Store     tsdb.Capabilities `json:"store"`
		Endpoints []string          `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Store.StoreContract != tsdb.StoreContract || len(got.Store.Views) == 0 || len(got.Store.Tables) == 0 {
		t.Fatalf("capabilities: %+v", got.Store)
	}
	if len(got.Endpoints) == 0 {
		t.Fatal("no endpoints listed")
	}
}
