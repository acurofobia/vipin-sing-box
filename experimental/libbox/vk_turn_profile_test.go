package libbox

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/protocol/vkturn"
)

func TestTURNProfilesValidateBeforeBootstrap(t *testing.T) {
	wg := vkturn.WireGuardConfig{PrivateKey: strings.Repeat("A", 43) + "=", PublicKey: strings.Repeat("A", 43) + "=", Address: "10.0.0.2/32", MTU: 1280}
	if err := validateTURNProfile(false, "", "", wg); err != nil {
		t.Fatal("SRTP profile rejected:", err)
	}
	if err := validateTURNProfile(true, "password", "installation", vkturn.WireGuardConfig{}); err != nil {
		t.Fatal("WRAP-A profile rejected:", err)
	}
	for _, input := range []struct {
		wrap             bool
		password, device string
		wg               vkturn.WireGuardConfig
	}{
		{true, "", "installation", wg}, {true, "password", "", wg}, {false, "", "", vkturn.WireGuardConfig{}},
		{false, "", "", vkturn.WireGuardConfig{PrivateKey: wg.PrivateKey, PublicKey: wg.PublicKey, PresharedKey: "bad", Address: wg.Address, MTU: 1280}},
	} {
		if err := validateTURNProfile(input.wrap, input.password, input.device, input.wg); err == nil {
			t.Fatal("invalid transport profile accepted")
		}
	}
}
