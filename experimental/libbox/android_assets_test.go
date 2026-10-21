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
	var route map[string]json.RawMessage
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatal(err)
	}
	var sets []map[string]any
	if err := json.Unmarshal(route["rule_set"], &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets) != 21 {
		t.Fatalf("packaged rule-set count=%d, expected21", len(sets))
	}
	// The runtime keeps remote descriptors and supplies a packaged initial_path.
	// Include the separate Russia-inside fallback so all 22 assets are decoded.
	sets = append(sets, map[string]any{
		"type": "remote", "tag": "russia-inside", "format": "binary",
		"url":         "https://github.com/itdoginfo/allow-domains/releases/latest/download/russia_inside.srs",
		"http_client": map[string]any{"detour": "vk-wg"}, "update_interval": "1d",
	})
	for _, set := range sets {
		if set["type"] != "remote" || set["url"] == "" {
			t.Fatal("bundled routing lost remote update descriptor")
		}
		client, ok := set["http_client"].(map[string]any)
		if !ok || client["detour"] != "vk-wg" {
			t.Fatal("remote rule updates bypass selected proxy")
		}
		tag, ok := set["tag"].(string)
		if !ok {
			t.Fatal("rule set has no tag")
		}
		absolute := filepath.Join(assets, "rulesets", tag+".srs")
		if _, err := os.Stat(absolute); err != nil {
			t.Fatal(err)
		}
		set["initial_path"] = absolute
	}
	route["rule_set"], _ = json.Marshal(sets)
	data, _ = json.Marshal(route)
	text, err := vkturn.BuildVLESSConfiguration(data, json.RawMessage(`{"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661"}`))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &config); err != nil {
		t.Fatal(err)
	}
	config["inbounds"] = json.RawMessage(`[{"type":"mixed","tag":"asset-test","listen":"127.0.0.1","listen_port":0}]`)
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
