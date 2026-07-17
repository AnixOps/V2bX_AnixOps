package nftablesforward

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyNftDocumentAcceptsExactTCPAndUDPState(t *testing.T) {
	config := verifiedForwardConfig(t)
	require.NoError(t, verifyNftDocument([]byte(verifiedForwardNftJSON()), config))
}

func TestVerifyNftDocumentRejectsKernelDrift(t *testing.T) {
	config := verifiedForwardConfig(t)
	tests := []struct {
		name      string
		mutate    func(string) string
		wantError string
	}{
		{
			name:      "priority",
			mutate:    func(document string) string { return strings.Replace(document, `"prio":-100`, `"prio":-90`, 1) },
			wantError: "base chain",
		},
		{
			name: "comment",
			mutate: func(document string) string {
				return strings.Replace(document, `"anixops tcp-443 dedicated"`, `"anixops tcp-443 altered"`, 1)
			},
			wantError: "not managed",
		},
		{
			name:      "dnat target",
			mutate:    func(document string) string { return strings.Replace(document, `"203.0.113.10"`, `"203.0.113.11"`, 1) },
			wantError: "DNAT target address",
		},
		{
			name: "unmanaged object",
			mutate: func(document string) string {
				return strings.Replace(document,
					`{"table":{"family":"inet","name":"anixops_forward","handle":1}}`,
					`{"set":{"family":"inet","table":"anixops_forward","name":"foreign"}},{"table":{"family":"inet","name":"anixops_forward","handle":1}}`,
					1,
				)
			},
			wantError: "unmanaged object",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyNftDocument([]byte(test.mutate(verifiedForwardNftJSON())), config)
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func verifiedForwardConfig(t *testing.T) Config {
	t.Helper()
	config, err := ParseConfig([]byte(`{
        "apply": true,
        "family": "inet",
        "table": "anixops_forward",
        "chain": "prerouting",
        "priority": -100,
        "rules": [
          {"id":"tcp-443","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443,"comment":"dedicated"},
          {"id":"udp-443","protocol":"udp","listen_address":"2001:db8::10","listen_port":443,"target_address":"2001:db8::20","target_port":8443}
        ]
    }`))
	require.NoError(t, err)
	return config
}

func verifiedForwardNftJSON() string {
	return `{"nftables":[
        {"metainfo":{"version":"1.0.6","json_schema_version":1}},
        {"table":{"family":"inet","name":"anixops_forward","handle":1}},
        {"chain":{"family":"inet","table":"anixops_forward","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
        {"rule":{"family":"inet","table":"anixops_forward","chain":"prerouting","handle":2,"comment":"anixops tcp-443 dedicated","expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.10"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
            {"dnat":{"family":"ip","addr":"203.0.113.10","port":8443}}
        ]}},
        {"rule":{"family":"inet","table":"anixops_forward","chain":"prerouting","handle":3,"comment":"anixops udp-443","expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"2001:db8::10"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},
            {"dnat":{"family":"ip6","addr":"2001:db8::20","port":8443}}
        ]}}
    ]}`
}
