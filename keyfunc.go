package keyfunc

import (
	"encoding/base64"
	"strings"

	"github.com/golang-jwt/jwt"
)

// Keyfunc matches the signature of github.com/golang-jwt/jwt's jwt.Keyfunc function.
func (j *JWKS) Keyfunc(token *jwt.Token) (interface{}, error) {
	keys := j.GetMatchingKeysWithRefresh(token)
	if len(keys) == 0 {
		return nil, ErrNoMatchingKey
	}
	// here we assume that there is only one key matching "kid"
	return keys[0].Public, nil
}

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
