package plugincontrol

import (
	"strings"
	"testing"
)

func TestValidateOperationRejectsGenerationRegression(t *testing.T) {
	operation := validOperation()
	if err := ValidateOperation(operation); err != nil {
		t.Fatalf("ValidateOperation() error = %v, want nil", err)
	}

	operation.Generation = 0
	err := ValidateOperation(operation)
	if err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("ValidateOperation() error = %v, want generation validation error", err)
	}
}

func TestValidateOperationRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name       string
		invalidate func(*Operation)
		wantError  string
	}{
		{
			name: "id",
			invalidate: func(operation *Operation) {
				operation.ID = ""
			},
			wantError: "id",
		},
		{
			name: "package id",
			invalidate: func(operation *Operation) {
				operation.PackageID = ""
			},
			wantError: "package id",
		},
		{
			name: "package version",
			invalidate: func(operation *Operation) {
				operation.PackageVersion = ""
			},
			wantError: "package version",
		},
		{
			name: "generation",
			invalidate: func(operation *Operation) {
				operation.Generation = 0
			},
			wantError: "generation",
		},
		{
			name: "idempotency key",
			invalidate: func(operation *Operation) {
				operation.IdempotencyKey = ""
			},
			wantError: "idempotency key",
		},
		{
			name: "kind",
			invalidate: func(operation *Operation) {
				operation.Kind = ""
			},
			wantError: "kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := validOperation()
			test.invalidate(&operation)

			err := ValidateOperation(operation)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateOperation() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateOperationRejectsInvalidConfigJSON(t *testing.T) {
	tests := []struct {
		name       string
		configJSON []byte
	}{
		{name: "malformed", configJSON: []byte("{")},
		{name: "empty", configJSON: []byte{}},
		{name: "nil"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := validOperation()
			operation.ConfigJSON = test.configJSON

			err := ValidateOperation(operation)
			if err == nil || !strings.Contains(err.Error(), "config") {
				t.Fatalf("ValidateOperation() error = %v, want config validation error", err)
			}
		})
	}
}

func validOperation() Operation {
	return Operation{
		ID:             "op-42",
		PackageID:      "wireguard",
		PackageVersion: "4.0.0",
		Generation:     9,
		IdempotencyKey: "key-42",
		Kind:           "configure",
		ConfigJSON:     []byte("{}"),
	}
}
