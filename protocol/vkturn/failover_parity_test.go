package vkturn

import (
	"encoding/json"
	"testing"
)

func TestVLESSFailoverConfigurationPreservesFourTags(t *testing.T) {
	route := json.RawMessage(`{"final":"vk-wg","rules":[],"rule_set":[{"type":"remote","tag":"test","format":"binary","url":"https://example.org/rules.srs","download_detour":"vk-wg"}]}`)
	nodes := []json.RawMessage{}
	for _, tag := range []string{"p", "b1", "b2", "b3"} {
		nodes = append(nodes, json.RawMessage(`{"type":"vless","tag":"`+tag+`","server":"example.org","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.org","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"abcd"}}}`))
	}
	text, err := BuildVLESSFailoverConfiguration(route, nodes, "b2")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []map[string]any
		Inbounds  []any
		Endpoints []any
		DNS       struct{ Servers []map[string]any }
		Route     json.RawMessage
	}
	if err := json.Unmarshal([]byte(text), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Outbounds) != 6 || len(config.Inbounds) != 1 || len(config.Endpoints) != 0 {
		t.Fatal("extra/missing engine components")
	}
	selector := config.Outbounds[5]
	if selector["type"] != "selector" || selector["tag"] != "vk-wg" || selector["default"] != "b2" || selector["interrupt_exist_connections"] != true {
		t.Fatal(selector)
	}
	for i, tag := range []string{"p", "b1", "b2", "b3"} {
		if config.Outbounds[i+1]["tag"] != tag || config.Outbounds[i+1]["domain_resolver"] == nil {
			t.Fatal("lost node/bootstrap")
		}
	}
	assertRoutingWithIPv6Guard(t, route, config.Route)
	if config.DNS.Servers[0]["detour"] != "vk-wg" || config.DNS.Servers[1]["detour"] != nil || config.DNS.Servers[1]["type"] != "https" || config.DNS.Servers[1]["server"] != "77.88.8.8" {
		t.Fatal("routing/bootstrap changed")
	}
	for _, bad := range [][]json.RawMessage{nodes[:3], {nodes[0], nodes[0], nodes[2], nodes[3]}} {
		if _, err := BuildVLESSFailoverConfiguration(route, bad, "p"); err == nil {
			t.Fatal("invalid nodes accepted")
		}
	}
	if _, err := BuildVLESSFailoverConfiguration(route, nodes, "missing"); err == nil {
		t.Fatal("missing primary accepted")
	}
}
