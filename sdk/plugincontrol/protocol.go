package plugincontrol

import (
	"encoding/json"
	"errors"
)

type Operation struct {
	ID             string
	PackageID      string
	PackageVersion string
	Generation     uint64
	IdempotencyKey string
	Kind           string
	ConfigJSON     []byte
}

type RuntimeStatus struct {
	PackageID      string
	PackageVersion string
	Generation     uint64
	Healthy        bool
	ObservedHash   string
	FailureCode    string
}

func ValidateOperation(operation Operation) error {
	switch {
	case operation.ID == "":
		return errors.New("plugin operation id is required")
	case operation.PackageID == "":
		return errors.New("plugin operation package id is required")
	case operation.PackageVersion == "":
		return errors.New("plugin operation package version is required")
	case operation.Generation == 0:
		return errors.New("plugin operation generation is required")
	case operation.IdempotencyKey == "":
		return errors.New("plugin operation idempotency key is required")
	case operation.Kind == "":
		return errors.New("plugin operation kind is required")
	case !json.Valid(operation.ConfigJSON):
		return errors.New("plugin operation config is not valid JSON")
	default:
		return nil
	}
}
