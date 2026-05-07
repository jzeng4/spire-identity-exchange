package utils

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestClaims_GetClaim(t *testing.T) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "test-subject",
			Issuer:  "test-issuer",
		},
		RawClaims: map[string]interface{}{
			"repository": "org/repo",
			"workflow":   "test-workflow",
			"custom":     "custom-value",
			"number":     float64(123),
			"boolean":    true,
		},
	}

	tests := []struct {
		name     string
		claimKey string
		expected interface{}
	}{
		{
			name:     "get string claim",
			claimKey: "repository",
			expected: "org/repo",
		},
		{
			name:     "get workflow claim",
			claimKey: "workflow",
			expected: "test-workflow",
		},
		{
			name:     "get custom claim",
			claimKey: "custom",
			expected: "custom-value",
		},
		{
			name:     "get number claim",
			claimKey: "number",
			expected: float64(123),
		},
		{
			name:     "get boolean claim",
			claimKey: "boolean",
			expected: true,
		},
		{
			name:     "get non-existent claim",
			claimKey: "nonexistent",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.RawClaims[tt.claimKey]
			if result != tt.expected {
				t.Errorf("RawClaims[%s] = %v, want %v", tt.claimKey, result, tt.expected)
			}
		})
	}
}

func TestClaims_GetStringClaim(t *testing.T) {
	claims := &Claims{
		RawClaims: map[string]interface{}{
			"string_claim":  "value",
			"number_claim":  float64(123),
			"boolean_claim": true,
			"nil_claim":     nil,
		},
	}

	tests := []struct {
		name     string
		claimKey string
		expected string
	}{
		{
			name:     "get valid string claim",
			claimKey: "string_claim",
			expected: "value",
		},
		{
			name:     "get number as string returns empty",
			claimKey: "number_claim",
			expected: "",
		},
		{
			name:     "get boolean as string returns empty",
			claimKey: "boolean_claim",
			expected: "",
		},
		{
			name:     "get nil claim returns empty",
			claimKey: "nil_claim",
			expected: "",
		},
		{
			name:     "get non-existent claim returns empty",
			claimKey: "nonexistent",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStringClaim(claims.RawClaims, tt.claimKey)
			if result != tt.expected {
				t.Errorf("GetStringClaim(%s) = %v, want %v", tt.claimKey, result, tt.expected)
			}
		})
	}
}

func TestClaims_SetRawClaims(t *testing.T) {
	claims := &Claims{}

	rawClaims := map[string]interface{}{
		"claim1": "value1",
		"claim2": "value2",
		"claim3": float64(3),
	}

	claims.RawClaims = rawClaims

	if claims.RawClaims == nil {
		t.Error("RawClaims should not be nil after setting")
	}

	for key, expectedValue := range rawClaims {
		actualValue := claims.RawClaims[key]
		if actualValue != expectedValue {
			t.Errorf("Claim %s = %v, want %v", key, actualValue, expectedValue)
		}
	}
}
