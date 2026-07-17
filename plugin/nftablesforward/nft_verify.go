package nftablesforward

import (
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

// verifyNftDocument proves that the kernel table is exactly the ruleset
// rendered from the signed plugin configuration. It intentionally rejects
// unmanaged objects rather than treating a merely reachable table as healthy.
func verifyNftDocument(contents []byte, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	var document nftForwardDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return fmt.Errorf("decode nftables JSON: %w", err)
	}
	if len(document.Objects) == 0 {
		return errors.New("nftables JSON document is empty")
	}

	expectedRules := make(map[string]Rule, len(config.Rules))
	for _, rule := range config.Rules {
		expectedRules[nftComment(rule)] = rule
	}
	tableCount, chainCount := 0, 0
	foundRules := make(map[string]bool, len(expectedRules))
	for _, raw := range document.Objects {
		var object nftForwardObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return fmt.Errorf("decode nftables object: %w", err)
		}
		kindCount := 0
		if len(object.MetaInfo) != 0 {
			kindCount++
		}
		if object.Table != nil {
			kindCount++
			tableCount++
			if object.Table.Family != config.Family || object.Table.Name != config.Table {
				return errors.New("nftables-forward table identity does not match desired state")
			}
		}
		if object.Chain != nil {
			kindCount++
			chainCount++
			priority, err := parseNftForwardInteger(object.Chain.Priority)
			if err != nil {
				return fmt.Errorf("decode nftables-forward chain priority: %w", err)
			}
			if object.Chain.Family != config.Family || object.Chain.Table != config.Table || object.Chain.Name != config.Chain ||
				object.Chain.Type != "nat" || object.Chain.Hook != "prerouting" || priority != config.Priority || object.Chain.Policy != "accept" {
				return errors.New("nftables-forward base chain does not match desired state")
			}
		}
		if object.Rule != nil {
			kindCount++
			expected, ok := expectedRules[object.Rule.Comment]
			if !ok {
				return errors.New("nftables-forward rule is not managed by the desired state")
			}
			if foundRules[object.Rule.Comment] {
				return fmt.Errorf("nftables-forward rule %q is duplicated", expected.ID)
			}
			if err := verifyNftForwardRule(*object.Rule, config, expected); err != nil {
				return fmt.Errorf("nftables-forward rule %q: %w", expected.ID, err)
			}
			foundRules[object.Rule.Comment] = true
		}
		if kindCount != 1 {
			return errors.New("nftables-forward table contains an unmanaged object")
		}
	}
	if tableCount != 1 || chainCount != 1 {
		return errors.New("nftables-forward table or base chain is missing or duplicated")
	}
	if len(foundRules) != len(expectedRules) {
		return errors.New("nftables-forward rules do not match desired state")
	}
	return nil
}

func verifyNftForwardRule(rule nftForwardRuleJSON, config Config, expected Rule) error {
	if rule.Family != config.Family || rule.Table != config.Table || rule.Chain != config.Chain || rule.Comment != nftComment(expected) {
		return errors.New("identity does not match desired state")
	}
	if len(rule.Expr) != 3 {
		return errors.New("contains an unexpected expression count")
	}
	expectedAddress, err := netip.ParseAddr(expected.ListenAddress)
	if err != nil {
		return errors.New("desired listen address is invalid")
	}
	expectedTarget, err := netip.ParseAddr(expected.TargetAddress)
	if err != nil {
		return errors.New("desired target address is invalid")
	}
	addressProtocol := nftAddressFamily(expected.ListenAddress)
	addressMatched, portMatched, dnatMatched := false, false, false
	for _, raw := range rule.Expr {
		var expression map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expression); err != nil {
			return fmt.Errorf("decode expression: %w", err)
		}
		if len(expression) != 1 {
			return errors.New("contains an unmanaged expression")
		}
		if matchRaw, ok := expression["match"]; ok {
			protocol, field, value, err := decodeNftForwardMatch(matchRaw)
			if err != nil {
				return err
			}
			switch {
			case protocol == addressProtocol && field == "daddr":
				address, err := parseNftForwardAddress(value)
				if err != nil || address != expectedAddress {
					return errors.New("destination address does not match desired state")
				}
				if addressMatched {
					return errors.New("destination address is duplicated")
				}
				addressMatched = true
			case protocol == expected.Protocol && field == "dport":
				port, err := parseNftForwardInteger(value)
				if err != nil || port != int(expected.ListenPort) {
					return errors.New("destination port does not match desired state")
				}
				if portMatched {
					return errors.New("destination port is duplicated")
				}
				portMatched = true
			default:
				return errors.New("contains an unmanaged match")
			}
			continue
		}
		if dnatRaw, ok := expression["dnat"]; ok {
			if dnatMatched {
				return errors.New("DNAT verdict is duplicated")
			}
			if err := verifyNftForwardDNAT(dnatRaw, addressProtocol, expectedTarget, expected.TargetPort); err != nil {
				return err
			}
			dnatMatched = true
			continue
		}
		return errors.New("contains an unmanaged verdict")
	}
	if !addressMatched || !portMatched || !dnatMatched {
		return errors.New("does not match desired state")
	}
	return nil
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
