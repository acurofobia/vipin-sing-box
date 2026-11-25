package vkturn

import (
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"testing"
)

func TestCancelledGenerationCannotRegisterLateBootstrap(t *testing.T) {
	generation := BeginSession()
	CancelSessions()
	p := proxy.NewProxy(proxy.Config{NumConns: 1})
	if _, err := AddSession(p, generation); err == nil {
		t.Fatal("bootstrap registered after cancellation")
	}
}

func TestNetworkChangeRejectsRetiredSessionAndGeneration(t *testing.T) {
	g := BeginSession()
	p := proxy.NewProxy(proxy.Config{NumConns: 1})
	defer p.Stop()
	sessionsMu.Lock()
	id := nextSession.Add(1)
	sessions[id] = p
	sessionsMu.Unlock()
	t.Cleanup(func() {
		sessionsMu.Lock()
		delete(sessions, id)
		sessionsMu.Unlock()
	})
	if NotifyNetworkChanged(id+1, g) || NotifyNetworkChanged(id, g-1) {
		t.Fatal("accepted an old network event")
	}
	if !NotifyNetworkChanged(id, g) {
		t.Fatal("current session did not receive network change")
	}
	InvalidateSessions()
	if NotifyNetworkChanged(id, g) {
		t.Fatal("accepted network event after cancellation")
	}
}
