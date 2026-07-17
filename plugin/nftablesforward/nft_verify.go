package nftablesforward

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type nftForwardDocument struct {
	Objects []json.RawMessage `json:"nftables"`
}

type nftForwardObject struct {
	MetaInfo json.RawMessage      `json:"metainfo"`
	Table    *nftForwardTableJSON `json:"table"`
	Chain    *nftForwardChainJSON `json:"chain"`
	Rule     *nftForwardRuleJSON  `json:"rule"`
}

type nftForwardTableJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftForwardChainJSON struct {
	Family   string          `json:"family"`
	Table    string          `json:"table"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Hook     string          `json:"hook"`
	Priority json.RawMessage `json:"prio"`
	Policy   string          `json:"policy"`
}

type nftForwardRuleJSON struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

// canonicalNftForwardState is the deterministic semantic representation used
// for the live-kernel fingerprint. It deliberately excludes nft's runtime
// handles, metainfo, and mutable packet/byte counters.
type canonicalNftForwardState struct {
	Version int                       `json:"version"`
	Family  string                    `json:"family"`
	Table   string                    `json:"table"`
	Chain   canonicalNftForwardChain  `json:"chain"`
	Rules   []canonicalNftForwardRule `json:"rules"`
}

type canonicalNftForwardChain struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority int    `json:"priority"`
	Policy   string `json:"policy"`
}

type canonicalNftForwardRule struct {
	ID            string `json:"id"`
	Comment       string `json:"comment"`
	Protocol      string `json:"protocol"`
	ListenAddress string `json:"listen_address"`
	ListenPort    uint16 `json:"listen_port"`
	TargetAddress string `json:"target_address"`
	TargetPort    uint16 `json:"target_port"`
}

// verifyNftDocument proves that the kernel table is exactly the ruleset
// rendered from the signed plugin configuration. It intentionally rejects
// unmanaged objects rather than treating a merely reachable table as healthy.
func verifyNftDocument(contents []byte, config Config) error {
	_, err := observeNftDocument(contents, config)
	return err
}

// observeNftDocument validates the complete managed table and returns the
// only live data that is allowed to leave the plugin: a deterministic semantic
// fingerprint and per-rule counter values. Every part of the fingerprint is
// checked against the signed configuration before it is emitted.
func observeNftDocument(contents []byte, config Config) (NftablesObservation, error) {
	if err := config.Validate(); err != nil {
		return NftablesObservation{}, err
	}
	var document nftForwardDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return NftablesObservation{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	if len(document.Objects) == 0 {
		return NftablesObservation{}, errors.New("nftables JSON document is empty")
	}

	expectedRules := make(map[string]int, len(config.Rules))
	for index, rule := range config.Rules {
		expectedRules[nftComment(rule)] = index
	}
	tableCount, chainCount := 0, 0
	foundRules := make(map[string]bool, len(expectedRules))
	counters := make([]NftablesRuleCounter, 0, len(expectedRules))
	for _, raw := range document.Objects {
		var object nftForwardObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return NftablesObservation{}, fmt.Errorf("decode nftables object: %w", err)
		}
		kindCount := 0
		if len(object.MetaInfo) != 0 {
			kindCount++
		}
		if object.Table != nil {
			kindCount++
			tableCount++
			if object.Table.Family != config.Family || object.Table.Name != config.Table {
				return NftablesObservation{}, errors.New("nftables-forward table identity does not match desired state")
			}
		}
		if object.Chain != nil {
			kindCount++
			chainCount++
			priority, err := parseNftForwardInteger(object.Chain.Priority)
			if err != nil {
				return NftablesObservation{}, fmt.Errorf("decode nftables-forward chain priority: %w", err)
			}
			if object.Chain.Family != config.Family || object.Chain.Table != config.Table || object.Chain.Name != config.Chain ||
				object.Chain.Type != "nat" || object.Chain.Hook != "prerouting" || priority != config.Priority || object.Chain.Policy != "accept" {
				return NftablesObservation{}, errors.New("nftables-forward base chain does not match desired state")
			}
		}
		if object.Rule != nil {
			kindCount++
			expectedIndex, ok := expectedRules[object.Rule.Comment]
			if !ok {
				return NftablesObservation{}, errors.New("nftables-forward rule is not managed by the desired state")
			}
			if foundRules[object.Rule.Comment] {
				return NftablesObservation{}, fmt.Errorf("nftables-forward rule %q is duplicated", config.Rules[expectedIndex].ID)
			}
			if expectedIndex != len(counters) {
				return NftablesObservation{}, errors.New("nftables-forward rule order does not match desired state")
			}
			counter, err := verifyNftForwardRule(*object.Rule, config, config.Rules[expectedIndex])
			if err != nil {
				return NftablesObservation{}, fmt.Errorf("nftables-forward rule %q: %w", config.Rules[expectedIndex].ID, err)
			}
			foundRules[object.Rule.Comment] = true
			counters = append(counters, counter)
		}
		if kindCount != 1 {
			return NftablesObservation{}, errors.New("nftables-forward table contains an unmanaged object")
		}
	}
	if tableCount != 1 || chainCount != 1 {
		return NftablesObservation{}, errors.New("nftables-forward table or base chain is missing or duplicated")
	}
	if len(foundRules) != len(expectedRules) {
		return NftablesObservation{}, errors.New("nftables-forward rules do not match desired state")
	}
	fingerprint, err := fingerprintNftForwardState(config)
	if err != nil {
		return NftablesObservation{}, err
	}
	return NftablesObservation{RulesetSHA256: fingerprint, RuleCounters: counters}, nil
}

func verifyNftForwardRule(rule nftForwardRuleJSON, config Config, expected Rule) (NftablesRuleCounter, error) {
	if rule.Family != config.Family || rule.Table != config.Table || rule.Chain != config.Chain || rule.Comment != nftComment(expected) {
		return NftablesRuleCounter{}, errors.New("identity does not match desired state")
	}
	if len(rule.Expr) != 4 {
		return NftablesRuleCounter{}, errors.New("contains an unexpected expression count")
	}
	expectedAddress, err := netip.ParseAddr(expected.ListenAddress)
	if err != nil {
		return NftablesRuleCounter{}, errors.New("desired listen address is invalid")
	}
	expectedTarget, err := netip.ParseAddr(expected.TargetAddress)
	if err != nil {
		return NftablesRuleCounter{}, errors.New("desired target address is invalid")
	}
	addressProtocol := nftAddressFamily(expected.ListenAddress)
	var counter NftablesRuleCounter
	for index, raw := range rule.Expr {
		var expression map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expression); err != nil {
			return NftablesRuleCounter{}, fmt.Errorf("decode expression: %w", err)
		}
		if len(expression) != 1 {
			return NftablesRuleCounter{}, errors.New("contains an unmanaged expression")
		}
		switch index {
		case 0, 1:
			matchRaw, ok := expression["match"]
			if !ok {
				return NftablesRuleCounter{}, errors.New("does not preserve signed match order")
			}
			protocol, field, value, err := decodeNftForwardMatch(matchRaw)
			if err != nil {
				return NftablesRuleCounter{}, err
			}
			switch index {
			case 0:
				if protocol != addressProtocol || field != "daddr" {
					return NftablesRuleCounter{}, errors.New("does not preserve signed destination address match")
				}
				address, err := parseNftForwardAddress(value)
				if err != nil || address != expectedAddress {
					return NftablesRuleCounter{}, errors.New("destination address does not match desired state")
				}
			case 1:
				if protocol != expected.Protocol || field != "dport" {
					return NftablesRuleCounter{}, errors.New("does not preserve signed destination port match")
				}
				port, err := parseNftForwardInteger(value)
				if err != nil || port != int(expected.ListenPort) {
					return NftablesRuleCounter{}, errors.New("destination port does not match desired state")
				}
			}
		case 2:
			counterRaw, ok := expression["counter"]
			if !ok {
				return NftablesRuleCounter{}, errors.New("does not contain a per-rule counter")
			}
			packets, bytes, err := decodeNftForwardCounter(counterRaw)
			if err != nil {
				return NftablesRuleCounter{}, err
			}
			counter = NftablesRuleCounter{RuleID: expected.ID, Packets: packets, Bytes: bytes}
		case 3:
			dnatRaw, ok := expression["dnat"]
			if !ok {
				return NftablesRuleCounter{}, errors.New("does not preserve signed DNAT verdict order")
			}
			if err := verifyNftForwardDNAT(dnatRaw, addressProtocol, expectedTarget, expected.TargetPort); err != nil {
				return NftablesRuleCounter{}, err
			}
		}
	}
	return counter, nil
}

func decodeNftForwardCounter(contents []byte) (uint64, uint64, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(contents, &fields); err != nil {
		return 0, 0, fmt.Errorf("decode counter: %w", err)
	}
	if len(fields) != 2 {
		return 0, 0, errors.New("counter is invalid")
	}
	packets, exists := fields["packets"]
	if !exists {
		return 0, 0, errors.New("counter packets are missing")
	}
	bytes, exists := fields["bytes"]
	if !exists {
		return 0, 0, errors.New("counter bytes are missing")
	}
	packetCount, err := parseNftForwardUint64(packets)
	if err != nil {
		return 0, 0, fmt.Errorf("decode counter packets: %w", err)
	}
	byteCount, err := parseNftForwardUint64(bytes)
	if err != nil {
		return 0, 0, fmt.Errorf("decode counter bytes: %w", err)
	}
	return packetCount, byteCount, nil
}

func fingerprintNftForwardState(config Config) (string, error) {
	canonical := canonicalNftForwardState{
		Version: 1,
		Family:  config.Family,
		Table:   config.Table,
		Chain: canonicalNftForwardChain{
			Name: config.Chain, Type: "nat", Hook: "prerouting", Priority: config.Priority, Policy: "accept",
		},
		Rules: make([]canonicalNftForwardRule, 0, len(config.Rules)),
	}
	for _, rule := range config.Rules {
		canonical.Rules = append(canonical.Rules, canonicalNftForwardRule{
			ID: rule.ID, Comment: nftComment(rule), Protocol: rule.Protocol,
			ListenAddress: rule.ListenAddress, ListenPort: rule.ListenPort,
			TargetAddress: rule.TargetAddress, TargetPort: rule.TargetPort,
		})
	}
	contents, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode canonical nftables-forward state: %w", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}

func decodeNftForwardMatch(contents []byte) (protocol, field string, value json.RawMessage, err error) {
	var match struct {
		Operator string          `json:"op"`
		Left     json.RawMessage `json:"left"`
		Right    json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(contents, &match); err != nil {
		return "", "", nil, fmt.Errorf("decode match: %w", err)
	}
	if match.Operator != "==" || len(match.Left) == 0 || len(match.Right) == 0 {
		return "", "", nil, errors.New("match is invalid")
	}
	var left struct {
		Payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(match.Left, &left); err != nil || left.Payload.Protocol == "" || left.Payload.Field == "" {
		return "", "", nil, errors.New("match payload is invalid")
	}
	return left.Payload.Protocol, left.Payload.Field, match.Right, nil
}

func verifyNftForwardDNAT(contents []byte, expectedFamily string, expectedAddress netip.Addr, expectedPort uint16) error {
	var dnat struct {
		Family string          `json:"family"`
		Addr   json.RawMessage `json:"addr"`
		Port   json.RawMessage `json:"port"`
	}
	if err := json.Unmarshal(contents, &dnat); err != nil {
		return fmt.Errorf("decode DNAT verdict: %w", err)
	}
	address, err := parseNftForwardAddress(dnat.Addr)
	if err != nil || dnat.Family != expectedFamily || address != expectedAddress {
		return errors.New("DNAT target address does not match desired state")
	}
	port, err := parseNftForwardInteger(dnat.Port)
	if err != nil || port != int(expectedPort) {
		return errors.New("DNAT target port does not match desired state")
	}
	return nil
}

func parseNftForwardAddress(raw json.RawMessage) (netip.Addr, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(text)
}

func parseNftForwardInteger(raw json.RawMessage) (int, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return 0, errors.New("numeric value is missing")
	}
	if strings.HasPrefix(text, "\"") {
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, err
		}
	}
	return strconv.Atoi(text)
}

func parseNftForwardUint64(raw json.RawMessage) (uint64, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" || strings.HasPrefix(text, "\"") {
		return 0, errors.New("unsigned numeric value is missing")
	}
	return strconv.ParseUint(text, 10, 64)
}
