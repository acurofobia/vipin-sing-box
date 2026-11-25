package libbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestBinaryRuleSetContainsIPCIDR(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		want       bool
	}{
		{"office-prefixes", `{"type":"logical","mode":"or","rules":[{"domain":"example.org"},{"ip_cidr":"192.0.2.0/24"}]}`, true},
		{"geoip-site", `{"domain":"example.org"}`, false},
		{"source-addresses", `{"source_ip_cidr":"192.0.2.0/24"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rules option.PlainRuleSet
			if err := json.Unmarshal([]byte(`{"rules":[`+tc.rule+`]}`), &rules); err != nil {
				t.Fatal(err)
			}
			var data bytes.Buffer
			if err := srs.Write(&data, rules, C.RuleSetVersionCurrent); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), tc.name+".srs")
			if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := BinaryRuleSetContainsIPCIDR(path)
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestInvalidBinaryRuleSetIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.srs")
	if err := os.WriteFile(path, []byte("SRS\x02invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BinaryRuleSetContainsIPCIDR(path); err == nil {
		t.Fatal("accepted invalid compiled rules")
	}
}

func TestBinaryRuleSetRequiresCompleteCompressedStream(t *testing.T) {
	var encoded bytes.Buffer
	if err := srs.Write(&encoded, option.PlainRuleSet{}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "truncated.srs")
	b := encoded.Bytes()
	if err := os.WriteFile(path, b[:len(b)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BinaryRuleSetContainsIPCIDR(path); err == nil {
		t.Fatal("accepted truncated compressed stream")
	}
}

func TestBinaryRuleSetRejectsBytesAfterCompressedStream(t *testing.T) {
	var encoded bytes.Buffer
	if err := srs.Write(&encoded, option.PlainRuleSet{}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trailing.srs")
	if err := os.WriteFile(path, append(encoded.Bytes(), []byte("trailing")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BinaryRuleSetContainsIPCIDR(path); err == nil {
		t.Fatal("accepted data after compiled rule stream")
	}
}
