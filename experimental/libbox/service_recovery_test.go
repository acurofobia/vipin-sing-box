package libbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type recoveryTestDialer struct{ calls atomic.Int32 }

func (d *recoveryTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return new(net.Dialer).DialContext(ctx, network, destination.String())
}

func (d *recoveryTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unused")
}

func recoveryTestClient(t *testing.T, ctx context.Context, server *httptest.Server) (*ServiceRecoveryClient, *recoveryTestDialer) {
	t.Helper()
	dialer := new(recoveryTestDialer)
	client, err := newServiceRecoveryClient(ctx, "operation", server.URL, dialer)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client.transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	t.Cleanup(client.Close)
	return client, dialer
}

func TestServiceRecoveryOriginLimitsAndRedirect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://other.invalid/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.Header.Get("X-HWID") != "original-device" {
			t.Error("request lost original HWID")
		}
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(202)
		_, _ = w.Write([]byte("pending"))
	}))
	defer server.Close()
	client, dialer := recoveryTestClient(t, context.Background(), server)
	response, err := client.Fetch(server.URL+"/subscription", `{"X-HWID":"original-device"}`, 1024, 1000)
	if err != nil || response.Status != 202 || string(response.Body) != "pending" || !strings.Contains(response.HeadersJSON, `"Retry-After":["7"]`) {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if dialer.calls.Load() == 0 {
		t.Fatal("request bypassed selected core transport")
	}
	response, err = client.Fetch(server.URL+"/redirect", `{}`, 1024, 1000)
	if err != nil || response.Status != 302 {
		t.Fatalf("redirect was followed: %+v %v", response, err)
	}
	before := calls.Load()
	for _, input := range []string{"https://other.invalid/secret", strings.Replace(server.URL, "https:", "http:", 1), "https://user:pass@" + strings.TrimPrefix(server.URL, "https://")} {
		if _, err := client.Fetch(input, `{}`, 1024, 1000); err == nil || !strings.HasPrefix(err.Error(), "invalid:") {
			t.Fatalf("accepted unsafe URL: %v", err)
		}
	}
	if calls.Load() != before {
		t.Fatal("invalid URL reached network")
	}
	if _, err := client.Fetch(server.URL, `{"X-HWID":"original-device"}`, 3, 1000); err == nil || !strings.HasPrefix(err.Error(), "invalid:") {
		t.Fatalf("accepted oversized body: %v", err)
	}
}

func TestServiceRecoveryCloseAndCoreCancellationAbortRequests(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "core", true: "client"}[closeClient], func(t *testing.T) {
			entered := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, _ := recoveryTestClient(t, ctx, server)
			result := make(chan error, 1)
			go func() { _, err := client.Fetch(server.URL, `{}`, 1024, 5000); result <- err }()
			<-entered
			if closeClient {
				client.Close()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil || !strings.HasPrefix(err.Error(), "cancelled:") {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("request outlived its session")
			}
			if _, err := client.Fetch(server.URL, `{}`, 1024, 1000); err == nil {
				t.Fatal("retired client opened a new request")
			}
		})
	}
}

func TestServiceRecoveryTLSFailureIsSanitized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := newServiceRecoveryClient(context.Background(), "operation", server.URL, new(recoveryTestDialer))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Fetch(server.URL+"/secret-token", `{}`, 1024, 1000)
	if err == nil || !strings.HasPrefix(err.Error(), "tls:") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("TLS failure lost classification or leaked path: %v", err)
	}
}
