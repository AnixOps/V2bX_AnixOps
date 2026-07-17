package nategress

import (
	"encoding/json"
	"errors"
	"fmt"
)

type nftDocument struct {
	Objects []json.RawMessage `json:"nftables"`
}

type nftObject struct {
	MetaInfo json.RawMessage `json:"metainfo"`
	Table    *nftTableJSON   `json:"table"`
	Chain    *nftChainJSON   `json:"chain"`
	Rule     *nftRuleJSON    `json:"rule"`
}

type nftTableJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftChainJSON struct {
	Family   string          `json:"family"`
	Table    string          `json:"table"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Hook     string          `json:"hook"`
	Priority json.RawMessage `json:"prio"`
	Policy   string          `json:"policy"`
}

type nftRuleJSON struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

func verifyNftDocument(contents []byte, config Config) error {
	var document nftDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return fmt.Errorf("decode nftables JSON: %w", err)
	}
	tableCount := 0
	chainCount := 0
	rules := make(map[string]bool, 2)
	for _, raw := range document.Objects {
		var object nftObject
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
			if object.Table.Family != "inet" || object.Table.Name != config.TableName {
				return errors.New("nat-egress nftables table identity does not match")
			}
		}
		if object.Chain != nil {
			kindCount++
			chainCount++
			priority, err := parseNumericJSON(object.Chain.Priority)
			if err != nil {
				return fmt.Errorf("decode nat-egress chain priority: %w", err)
			}
			if object.Chain.Family != "inet" || object.Chain.Table != config.TableName || object.Chain.Name != config.ChainName ||
				object.Chain.Type != "nat" || object.Chain.Hook != "postrouting" || priority != nftPriority || object.Chain.Policy != "accept" {
				return errors.New("nat-egress nftables base chain does not match desired state")
			}
		}
		if object.Rule != nil {
			kindCount++
			if object.Rule.Family != "inet" || object.Rule.Table != config.TableName || object.Rule.Chain != config.ChainName {
				return errors.New("nat-egress nftables rule is outside the managed chain")
			}
			family, err := verifyNftRule(*object.Rule, config.EgressInterface)
			if err != nil {
				return err
			}
			if rules[family] {
				return fmt.Errorf("nat-egress nftables %s rule is duplicated", family)
			}
			rules[family] = true
		}
		if kindCount != 1 {
			return errors.New("nat-egress nftables table contains an unmanaged object")
		}
	}
	if tableCount != 1 || chainCount != 1 {
		return errors.New("nat-egress nftables table or base chain is missing or duplicated")
	}
	if rules["ipv4"] != config.IPv4Masquerade || rules["ipv6"] != config.IPv6Masquerade {
		return errors.New("nat-egress nftables address-family rules do not match desired state")
	}
	return nil
}

func verifyNftRule(rule nftRuleJSON, egressInterface string) (string, error) {
	family := ""
	interfaceMatch := false
	masquerade := false
	for _, raw := range rule.Expr {
		var expression map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expression); err != nil {
			return "", fmt.Errorf("decode nat-egress nftables expression: %w", err)
		}
		if len(expression) != 1 {
			return "", errors.New("nat-egress nftables rule contains an unmanaged expression")
		}
		if matchRaw, ok := expression["match"]; ok {
			key, value, err := decodeNftMetaMatch(matchRaw)
			if err != nil {
				return "", err
			}
			switch key {
			case "nfproto":
				if value != "ipv4" && value != "ipv6" {
					return "", errors.New("nat-egress nftables nfproto match is invalid")
				}
				family = value
			case "oifname":
				if value != egressInterface {
					return "", errors.New("nat-egress nftables egress interface does not match")
				}
				interfaceMatch = true
			default:
				return "", errors.New("nat-egress nftables rule contains an unmanaged match")
			}
			continue
		}
		if value, ok := expression["masquerade"]; ok && string(value) == "null" {
			masquerade = true
			continue
		}
		return "", errors.New("nat-egress nftables rule contains an unmanaged verdict")
	}
	if family == "" || !interfaceMatch || !masquerade || len(rule.Expr) != 3 {
		return "", errors.New("nat-egress nftables rule does not match desired state")
	}
	if rule.Comment != "anixops:nat-egress:"+family {
		return "", errors.New("nat-egress nftables rule comment does not match desired state")
	}
	return family, nil
}

func decodeNftMetaMatch(contents []byte) (string, string, error) {
	var match struct {
		Operator string `json:"op"`
		Left     struct {
			Meta struct {
				Key string `json:"key"`
			} `json:"meta"`
		} `json:"left"`
		Right string `json:"right"`
	}
	if err := json.Unmarshal(contents, &match); err != nil {
		return "", "", fmt.Errorf("decode nat-egress nftables match: %w", err)
	}
	if match.Operator != "==" || match.Left.Meta.Key == "" {
		return "", "", errors.New("nat-egress nftables match is invalid")
	}
	return match.Left.Meta.Key, match.Right, nil
}
