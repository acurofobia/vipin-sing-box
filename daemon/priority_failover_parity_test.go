package daemon

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestPriorityLiveConnectionStatus(t *testing.T) {
	var c *priorityFailoverController
	b := &priorityTestBackend{selected: "p"}
	b.probe = func(ctx context.Context, tag string) (bool, error) {
		data, err := json.Marshal(c.Status())
		if err != nil {
			t.Fatal(err)
		}
		var state struct {
			Checking      string `json:"checking"`
			CheckingIndex int    `json:"checkingIndex"`
			Total         int    `json:"total"`
		}
		if err = json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		index := 1
		if tag == "b1" {
			index = 2
		}
		if state.Checking != tag || state.CheckingIndex != index || state.Total != 4 {
			t.Fatalf("live attempt missing: %s", data)
		}
		return tag == "b1", nil
	}
	c = testPriorityController(t, b)
	c.cycle(true)
	data, _ := json.Marshal(c.Status())
	var state struct {
		Selected       string `json:"selected"`
		SelectedHealth string `json:"selectedHealth"`
		SelectedIndex  int    `json:"selectedIndex"`
		Checking       string `json:"checking"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Selected != "b1" || state.SelectedHealth != "up" || state.SelectedIndex != 2 || state.Checking != "" {
		t.Fatalf("successful backup not reported: %s", data)
	}
}

func TestPriorityServerHealthSnapshot(t *testing.T) {
	b := &priorityTestBackend{selected: "p", results: map[string][]bool{"p": {false}, "b1": {true}}}
	c := testPriorityController(t, b)
	c.cycle(true)
	data, err := json.Marshal(c.Status())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Servers []struct{ Tag, Health string }
	}
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Servers) != 4 {
		t.Fatalf("expected four ordered servers: %s", data)
	}
	for i, health := range []string{"down", "up", "unknown", "unknown"} {
		if snapshot.Servers[i].Tag != []string{"p", "b1", "b2", "b3"}[i] || snapshot.Servers[i].Health != health {
			t.Fatalf("incorrect server health: %s", data)
		}
	}
	if err = c.Manual("b2"); err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(c.Status())
	_ = json.Unmarshal(data, &snapshot)
	for _, server := range snapshot.Servers {
		if server.Health != "unknown" {
			t.Fatalf("manual selection retained old health: %s", data)
		}
	}
}

func TestPriorityServerHealthExpires(t *testing.T) {
	b := &priorityTestBackend{selected: "p", results: map[string][]bool{"p": {false}, "b1": {false}, "b2": {true}}}
	c := testPriorityController(t, b)
	c.cycle(true)
	c.observedAt[1] = time.Now().Add(-time.Hour)
	state := c.Status()
	if state.Servers[1].Health != "unknown" || state.Servers[0].Health != "down" || state.SelectedHealth != "up" {
		t.Fatalf("stale backup retained a live health claim: %+v", state)
	}
}

func TestPriorityPauseDiscardsInterruptedProbeWithoutLosingFailures(t *testing.T) {
	b := &priorityTestBackend{selected: "p", results: map[string][]bool{"p": {false, false}, "b1": {true}}}
	c := testPriorityController(t, b)
	c.cycle(false)
	entered := make(chan struct{})
	done := make(chan struct{})
	b.probe = func(ctx context.Context, tag string) (bool, error) {
		close(entered)
		<-ctx.Done()
		// Even a late success must not overwrite the completed failure.
		return true, nil
	}
	go func() { c.cycle(false); close(done) }()
	<-entered
	c.SetPaused(true)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sleep did not cancel the probe")
	}
	b.probe = nil
	c.SetPaused(false)
	c.cycle(false)
	if b.Selected() != "b1" {
		t.Fatal("interrupted probe discarded the previous failure")
	}
}

func TestPriorityManualSelectionStillResetsFailuresAfterWake(t *testing.T) {
	b := &priorityTestBackend{selected: "p", results: map[string][]bool{"p": {false, false}, "b1": {false}, "b2": {true}}}
	c := testPriorityController(t, b)
	c.cycle(false)
	c.SetPaused(true)
	c.SetPaused(false)
	if err := c.Manual("b1"); err != nil {
		t.Fatal(err)
	}
	if c.failures != 0 {
		t.Fatal("manual selection retained failures from another server")
	}
	c.Resume()
	c.cycle(false)
	if b.Selected() != "b1" {
		t.Fatal("manual selection reused failures from another server")
	}
}

func TestPriorityAllDownExpiresWithObservations(t *testing.T) {
	b := &priorityTestBackend{selected: "p", results: map[string][]bool{}}
	c := testPriorityController(t, b)
	c.cycle(true)
	if !c.Status().AllDown {
		t.Fatal("expected all down")
	}
	for i := range c.observedAt {
		c.observedAt[i] = time.Now().Add(-time.Hour)
	}
	state := c.Status()
	if state.AllDown || state.PrimaryHealth != "unknown" {
		t.Fatalf("stale failure state: %+v", state)
	}
}
