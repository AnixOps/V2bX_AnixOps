package nategress

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyNftDocumentAcceptsExactDesiredState(t *testing.T) {
	config := validConfig()
	require.NoError(t, verifyNftDocument([]byte(validNftJSON()), config))
}

func TestVerifyNftDocumentRejectsSimilarChainAndComment(t *testing.T) {
	config := validConfig()
	wrongChain := strings.Replace(validNftJSON(), `"name":"postrouting"`, `"name":"postrouting_extra"`, 1)
	require.ErrorContains(t, verifyNftDocument([]byte(wrongChain), config), "base chain")
	wrongComment := strings.Replace(validNftJSON(), `"anixops:nat-egress:ipv4"`, `"prefix-anixops:nat-egress:ipv4"`, 1)
	require.ErrorContains(t, verifyNftDocument([]byte(wrongComment), config), "comment")
}

func TestVerifyNftDocumentRejectsUnmanagedObjects(t *testing.T) {
	config := validConfig()
	withSet := strings.Replace(validNftJSON(),
		`{"table":{"family":"inet","name":"anixops_nat_egress","handle":1}}`,
		`{"set":{"family":"inet","table":"anixops_nat_egress","name":"foreign"}},{"table":{"family":"inet","name":"anixops_nat_egress","handle":1}}`,
		1,
	)
	require.ErrorContains(t, verifyNftDocument([]byte(withSet), config), "unmanaged object")
}

func validNftJSON() string {
	return `{"nftables":[
		{"metainfo":{"version":"1.0.6","json_schema_version":1}},
		{"table":{"family":"inet","name":"anixops_nat_egress","handle":1}},
		{"chain":{"family":"inet","table":"anixops_nat_egress","name":"postrouting","handle":1,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
		{"rule":{"family":"inet","table":"anixops_nat_egress","chain":"postrouting","handle":2,"comment":"anixops:nat-egress:ipv4","expr":[
			{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
			{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},
			{"masquerade":null}
		]}}
	]}`
}
