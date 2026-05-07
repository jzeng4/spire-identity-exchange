package utils

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims with both standard and raw claims
type Claims struct {
	jwt.RegisteredClaims

	// RawClaims stores all claims from the token for claimProcessor processing
	RawClaims map[string]interface{} `json:"-"`
}

// UnmarshalJSON implements json.Unmarshaler to populate both RegisteredClaims and RawClaims
func (c *Claims) UnmarshalJSON(data []byte) error {
	// First, unmarshal into RegisteredClaims
	if err := json.Unmarshal(data, &c.RegisteredClaims); err != nil {
		return err
	}

	// Then, unmarshal into RawClaims to get all claims
	if c.RawClaims == nil {
		c.RawClaims = make(map[string]interface{})
	}
	return json.Unmarshal(data, &c.RawClaims)
}
