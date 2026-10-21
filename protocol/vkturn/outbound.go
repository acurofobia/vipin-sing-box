package vkturn

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var sessionsMu sync.Mutex
var sessions = make(map[int64]*proxy.Proxy)
var retiring = make(map[int64]chan struct{})
var nextSession atomic.Int64
var generation int64

func BeginSession() int64 {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	generation++
	return generation
}

func AddSession(p *proxy.Proxy, expectedGeneration int64) (int64, error) {
	sessionsMu.Lock()
	if expectedGeneration != generation {
		sessionsMu.Unlock()
		return 0, fmt.Errorf("VK TURN startup cancelled")
	}
	id := nextSession.Add(1)
	sessions[id] = p
	// The startup sentinel is acquired while registration is locked, so Stop
	// cannot observe an empty WaitGroup before the start goroutine is scheduled.
	p.StartAsync()
	sessionsMu.Unlock()
	return id, nil
}
func StopSession(id int64) {
	sessionsMu.Lock()
	p := sessions[id]
	delete(sessions, id)
	var finished chan struct{}
	if p != nil {
		finished = make(chan struct{})
		retiring[id] = finished
	}
	sessionsMu.Unlock()
	if p != nil {
		proxy.ClosePhysicalSockets()
		go func() {
			p.Stop()
			sessionsMu.Lock()
			delete(retiring, id)
			close(finished)
			sessionsMu.Unlock()
		}()
		select {
		case <-finished:
		case <-time.After(15 * time.Second):
		}
	}
}

func SessionsStopped() bool {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	return len(sessions) == 0 && len(retiring) == 0
}

func InvalidateSessions() {
	sessionsMu.Lock()
	generation++
	sessionsMu.Unlock()
}

func CheckSession(id, expectedGeneration int64) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if expectedGeneration != generation || sessions[id] == nil || sessions[id].Stopped() {
		return fmt.Errorf("VK TURN startup cancelled")
	}
	return nil
}

type Options struct {
	Session int64 `json:"session"`
}
type Outbound struct {
	outbound.Adapter
	proxy *proxy.Proxy
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[Options](registry, "vk-turn-transport", NewOutbound)
}
func NewOutbound(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	sessionsMu.Lock()
	p := sessions[options.Session]
	sessionsMu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("VK TURN session is not prepared")
	}
	return &Outbound{Adapter: outbound.NewAdapter("vk-turn-transport", tag, []string{N.NetworkUDP}, nil), proxy: p}, nil
}
func (o *Outbound) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkUDP {
		return nil, fmt.Errorf("VK TURN transport accepts WireGuard UDP packets only")
	}
	return newPacketConn(o.proxy), nil
}
func (o *Outbound) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return newPacketConn(o.proxy), nil
}

// CancelSessions also cancels bootstrap before its handle has reached Swift.
func CancelSessions() {
	sessionsMu.Lock()
	generation++
	ids := make([]int64, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	sessionsMu.Unlock()
	for _, id := range ids {
		StopSession(id)
	}
}

func SessionStats(id int64) proxy.Stats {
	sessionsMu.Lock()
	p := sessions[id]
	sessionsMu.Unlock()
	if p == nil {
		return proxy.Stats{}
	}
	return p.GetStats()
}

func SessionError(id int64) string {
	sessionsMu.Lock()
	p := sessions[id]
	sessionsMu.Unlock()
	if p == nil {
		return ""
	}
	return p.TerminalError()
}
