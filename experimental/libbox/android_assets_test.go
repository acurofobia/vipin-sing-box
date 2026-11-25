package libbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vkturn"
	"github.com/sagernet/sing/service/filemanager"
)

// Starts the actual router against every packaged .srs, without host TUN routes
// or external connections. This catches unsupported asset formats and lost tags.
func TestAndroidBundledRoutingStartsWithAllRuleSets(t *testing.T) {
	assets, err := filepath.Abs("../../../../app/src/main/assets")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(assets, "routing.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Assets   map[string]struct{ File string }
		Profiles map[string]struct {
			Rules []json.RawMessage
			Final string
		}
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Assets) != 22 || len(document.Profiles) != 2 {
		t.Fatal("bundled routing must include both profiles and all 22 SRS files")
	}
	for name, profile := range document.Profiles {
		t.Run(name, func(t *testing.T) {
			tags := map[string]bool{}
			for _, raw := range profile.Rules {
				var rule struct {
					RuleSet any `json:"rule_set"`
				}
				if err := json.Unmarshal(raw, &rule); err != nil {
					t.Fatal(err)
				}
				switch values := rule.RuleSet.(type) {
				case string:
					tags[values] = true
				case []any:
					for _, value := range values {
						tags[value.(string)] = true
					}
				}
			}
			var sets []map[string]string
			for tag := range tags {
				path := filepath.Join(assets, "rulesets", document.Assets[tag].File)
				hasIP, err := BinaryRuleSetContainsIPCIDR(path)
				if err != nil || hasIP != (tag == "geoip-direct") {
					t.Fatalf("bundled %s: IP matches=%v, err=%v", tag, hasIP, err)
				}
				sets = append(sets, map[string]string{"type": "local", "format": "binary", "tag": tag, "path": path})
			}
			route, err := json.Marshal(map[string]any{"rules": profile.Rules, "final": profile.Final, "rule_set": sets})
			if err != nil {
				t.Fatal(err)
			}
			startBundledRouter(t, route)
		})
	}
}

func startBundledRouter(t *testing.T, data []byte) {
	t.Helper()
	text, err := vkturn.BuildVLESSConfiguration(data, json.RawMessage(`{"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661"}`))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &config); err != nil {
		t.Fatal(err)
	}
	delete(config, "inbounds")
	config["log"] = json.RawMessage(`{"disabled":true}`)
	data, _ = json.Marshal(config)
	directory := t.TempDir()
	ctx := filemanager.WithDefault(include.Context(context.Background()), directory, directory, -1, -1)
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, data); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatalf("native core rejected packaged routing/rule sets: %v", err)
	}
	if outbound, found := instance.Outbound().Outbound("vk-wg"); !found || outbound.Type() != "vless" {
		t.Fatal("active target missing")
	}
}
