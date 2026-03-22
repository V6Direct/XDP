package models_test

import (
	"testing"
	"time"

	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
	"github.com/nsp/ddos-platform/pkg/types"
)

func TestAlertStoreAdd(t *testing.T) {
	s := models.NewAlertStore(10)
	s.Add(types.Alert{Level: "info", Message: "test1", Timestamp: time.Now()})
	s.Add(types.Alert{Level: "warning", Message: "test2", Timestamp: time.Now()})

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
}

func TestAlertStoreCapacity(t *testing.T) {
	const cap = 5
	s := models.NewAlertStore(cap)

	for i := 0; i < cap+3; i++ {
		s.Add(types.Alert{
			Level:     "info",
			Message:   "alert",
			Timestamp: time.Now(),
		})
	}

	list := s.List()
	if len(list) != cap {
		t.Errorf("len = %d, want %d (capacity)", len(list), cap)
	}
}

func TestAlertStoreNewestFirst(t *testing.T) {
	s := models.NewAlertStore(10)

	s.Add(types.Alert{Level: "info", Message: "first", Timestamp: time.Now()})
	time.Sleep(time.Millisecond)
	s.Add(types.Alert{Level: "critical", Message: "second", Timestamp: time.Now()})

	list := s.List()
	if len(list) < 2 {
		t.Fatalf("need at least 2 alerts, got %d", len(list))
	}
	// List returns newest first
	if list[0].Message != "second" {
		t.Errorf("first item = %q, want 'second' (newest)", list[0].Message)
	}
	if list[1].Message != "first" {
		t.Errorf("second item = %q, want 'first' (oldest)", list[1].Message)
	}
}

func TestAlertStoreIDAssigned(t *testing.T) {
	s := models.NewAlertStore(10)
	s.Add(types.Alert{Level: "info", Timestamp: time.Now()})
	s.Add(types.Alert{Level: "warning", Timestamp: time.Now()})

	list := s.List()
	for i, a := range list {
		if a.ID == "" {
			t.Errorf("alert[%d].ID is empty — ID should be auto-assigned", i)
		}
	}
	// IDs should be unique
	if len(list) >= 2 && list[0].ID == list[1].ID {
		t.Errorf("duplicate IDs: %q", list[0].ID)
	}
}

func TestAlertStoreEmpty(t *testing.T) {
	s := models.NewAlertStore(10)
	list := s.List()
	if list == nil {
		t.Error("List() should return empty slice, not nil")
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

func TestAlertStoreEvictsOldest(t *testing.T) {
	s := models.NewAlertStore(3)

	s.Add(types.Alert{Message: "A", Timestamp: time.Now()})
	s.Add(types.Alert{Message: "B", Timestamp: time.Now()})
	s.Add(types.Alert{Message: "C", Timestamp: time.Now()})
	// D pushes out A
	s.Add(types.Alert{Message: "D", Timestamp: time.Now()})

	list := s.List()
	for _, a := range list {
		if a.Message == "A" {
			t.Error("oldest alert 'A' should have been evicted")
		}
	}
	// D should be present (newest)
	found := false
	for _, a := range list {
		if a.Message == "D" {
			found = true
		}
	}
	if !found {
		t.Error("newest alert 'D' not found in list")
	}
}
