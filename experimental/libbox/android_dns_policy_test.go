package libbox

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// The JVM test compares this fixture's DNS rules to the Android policy builder's output.
// Loopback DNS responders record which resolver actually receives each A question.
func TestAndroidDNSResolverOrder(t *testing.T) {
	data, err := os.ReadFile("../../../../app/src/test/resources/routing-dns-conflict.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Route    map[string]any
		Expected json.RawMessage
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	ruleFile, err := os.Create(filepath.Join(t.TempDir(), "office.srs"))
	if err != nil {
		t.Fatal(err)
	}
	var rules option.PlainRuleSet
	if err := json.Unmarshal([]byte(`{"rules":[{"ip_cidr":"198.51.100.2/32"}]}`), &rules); err != nil {
		t.Fatal(err)
	}
	if err := srs.Write(ruleFile, rules, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	if err := ruleFile.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.Route["rule_set"] = []map[string]string{{"type": "local", "format": "binary", "tag": "office", "path": ruleFile.Name()}}

	var mu sync.Mutex
	requests := map[string][]string{}
	var servers []map[string]any
	for _, tag := range []string{"dns", "dns-direct"} {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) },
			Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				name := strings.TrimSuffix(q.Question[0].Name, ".")
				mu.Lock()
				requests[name] = append(requests[name], tag)
				mu.Unlock()
				ip := net.IPv4(192, 0, 2, 1)
				if name == "reject.priority.invalid" || name == "manual.invalid" {
					ip = net.IPv4(198, 51, 100, 2)
				}
				answer := new(dns.Msg).SetReply(q)
				answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
				if err := w.WriteMsg(answer); err != nil {
					t.Error(err)
				}
			})}
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				t.Error(err)
			}
		}()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
		servers = append(servers, map[string]any{"tag": tag, "type": "udp", "server": "127.0.0.1", "server_port": conn.LocalAddr().(*net.UDPAddr).Port})
	}
	config, err := json.Marshal(map[string]any{
		"log": map[string]bool{"disabled": true}, "route": fixture.Route,
		"dns":       map[string]any{"servers": servers, "rules": fixture.Expected, "final": "dns-direct"},
		"outbounds": []map[string]string{{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "vk-wg"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, config); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	router := service.FromContext[adapter.DNSRouter](ctx)
	for _, tc := range []struct {
		name, server string
		reject       bool
	}{
		{"manual.invalid", "dns-direct", false}, {"priority.invalid", "dns-direct", false},
		{"sub.priority.invalid", "dns", false}, {"reject.priority.invalid", "dns", true}, {"other.invalid", "dns-direct", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			q := new(dns.Msg).SetQuestion(dns.Fqdn(tc.name), dns.TypeA)
			reply, err := router.Exchange(deadline, q, adapter.DNSQueryOptions{})
			if err != nil {
				t.Fatal(err)
			}
			want := dns.RcodeSuccess
			if tc.reject {
				want = dns.RcodeRefused
			}
			if reply.Rcode != want {
				t.Fatalf("rcode %d; want %d", reply.Rcode, want)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(requests[tc.name], []string{tc.server}) {
				t.Fatalf("resolver sequence %v; want %s", requests[tc.name], tc.server)
			}
		})
	}
}
