package daemon

import "testing"

func TestServiceRecoveryNeverFallsBackToDirectOutbound(t *testing.T) {
	started := outboundProbeService(t, `{"outbounds":[{"type":"direct","tag":"vk-wg"}],"route":{"final":"vk-wg"}}`)
	defer started.CloseService()
	for _, tag := range []string{"vk-wg", "missing", ""} {
		if _, _, err := started.ServiceRecoveryTransport(tag); err == nil {
			t.Fatalf("accepted non-WireGuard recovery transport %q", tag)
		}
	}
	if err := started.CloseService(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := started.ServiceRecoveryTransport("vk-wg"); err == nil {
		t.Fatal("stopped core provided recovery transport")
	}
}
