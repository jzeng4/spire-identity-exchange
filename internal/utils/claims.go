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
	// Reset RegisteredClaims so a reused Claims value doesn't leak fields from a
	// prior token (e.g. an old Audience or ExpiresAt) into the new one.
	c.RegisteredClaims = jwt.RegisteredClaims{}
	if err := json.Unmarshal(data, &c.RegisteredClaims); err != nil {
		return err
	}

	// Always allocate a fresh map; unmarshalling into a non-nil map updates keys but
	// does not delete keys absent from the new payload, which would leak claims
	// across tokens if Claims is reused.
	c.RawClaims = make(map[string]interface{})
	return json.Unmarshal(data, &c.RawClaims)
}
