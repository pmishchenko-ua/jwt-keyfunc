package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	// ErrJWKAlgMismatch indicates that the given JWK was found, but its "alg" parameter's value did not match that of
	// the JWT.
	ErrJWKAlgMismatch = errors.New(`the given JWK was found, but its "alg" parameter's value did not match the expected algorithm`)

	// ErrNoMatchingKey indicated no JWKey is matching the token according ti SingleStore rules.
	ErrNoMatchingKey = errors.New("no key can be matched to validate the token")

	// ErrMissingAssets indicates there are required assets are missing to create a public key.
	ErrMissingAssets = errors.New("required assets are missing to create a public key")
)

// ErrorHandler is a function signature that consumes an error.
type ErrorHandler func(err error)

const (
	// UseEncryption is a JWK "use" parameter value indicating the JSON Web Key is to be used for encryption.
	UseEncryption JWKUse = "enc"
	// UseOmitted is a JWK "use" parameter value that was not specified or was empty.
	UseOmitted JWKUse = ""
	// UseSignature is a JWK "use" parameter value indicating the JSON Web Key is to be used for signatures.
	UseSignature JWKUse = "sig"
)

// JWKUse is a set of values for the "use" parameter of a JWK.
// See https://tools.ietf.org/html/rfc7517#section-4.2.
type JWKUse string

// JsonWebKey represents a JSON Web Key inside a JWKS.
type JsonWebKey struct {
	Algorithm    string      `json:"alg"`
	Curve        string      `json:"crv"`
	Exponent     string      `json:"e"`
	K            string      `json:"k"`
	ID           string      `json:"kid"`
	Modulus      string      `json:"n"`
	Type         string      `json:"kty"`
	Use          string      `json:"use"`
	X            string      `json:"x"`
	Y            string      `json:"y"`
	UsernameFrom string      `json:"usernameFrom"`
	Audience     interface{} `json:"aud"`
}

// parsedJWK represents a JSON Web Key parsed with fields as the correct Go types.
type ParsedJWK struct {
	algorithm string
	kty       string
	Public    interface{}
	use       JWKUse
	Jwk       *JsonWebKey
	kid       string
	audience  []string
}

// JWKS represents a JSON Web Key Set (JWK Set).
type JWKS struct {
	jwkUseWhitelist     map[JWKUse]struct{}
	cancel              context.CancelFunc
	client              *http.Client
	ctx                 context.Context
	raw                 []byte
	givenKeys           map[string]GivenKey
	givenKIDOverride    bool
	jwksURL             string
	keys                map[string][]ParsedJWK
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     time.Duration
	refreshRateLimit    time.Duration
	refreshRequests     chan context.CancelFunc
	refreshTimeout      time.Duration
	initAsync           bool
	refreshUnknownKID   bool
	requestFactory      func(ctx context.Context, url string) (*http.Request, error)
	responseExtractor   func(ctx context.Context, resp *http.Response) (json.RawMessage, error)
}

// rawJWKS represents a JWKS in JSON format.
type rawJWKS struct {
	Keys []*JsonWebKey `json:"keys"`
}

// NewJSON creates a new JWKS from a raw JSON message.
func NewJSON(jwksBytes json.RawMessage) (jwks *JWKS, err error) {
	var rawKS rawJWKS
	err = json.Unmarshal(jwksBytes, &rawKS)
	if err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKS. Add them to the JWKS.
	jwks = &JWKS{
		keys: make(map[string][]ParsedJWK, len(rawKS.Keys)),
	}
	for _, key := range rawKS.Keys {
		var keyInter interface{}
		switch keyType := key.Type; keyType {
		case ktyEC:
			keyInter, err = key.ECDSA()
			if err != nil {
				continue
			}
		case ktyOKP:
			keyInter, err = key.EdDSA()
			if err != nil {
				continue
			}
		case ktyOct:
			keyInter, err = key.Oct()
			if err != nil {
				continue
			}
		case ktyRSA:
			keyInter, err = key.RSA()
			if err != nil {
				continue
			}
		default:
			// Ignore unknown key types silently.
			continue
		}
		audience := make([]string, 0)
		if key.Audience != nil {
			if audStr, ok := key.Audience.(string); ok {
				audience = strings.Split(audStr, ",")
			} else if audList, ok := key.Audience.([]string); ok {
				audience = audList
			}
		}
		for idx := range audience {
			audience[idx] = strings.TrimSpace(audience[idx])
		}

		jwks.keys[key.ID] = append(jwks.keys[key.ID],
			ParsedJWK{
				algorithm: key.Algorithm,
				kty:       key.Type,
				use:       JWKUse(key.Use),
				Public:    keyInter,
				Jwk:       key,
				kid:       key.ID,
				audience:  audience,
			})
	}

	return jwks, nil
}

// EndBackground ends the background goroutine to update the JWKS. It can only happen once and is only effective if the
// JWKS has a background goroutine refreshing the JWKS keys.
func (j *JWKS) EndBackground() {
	if j.cancel != nil {
		j.cancel()
	}
}

// KIDs returns the key IDs (`kid`) for all keys in the JWKS.
func (j *JWKS) KIDs() (kids []string) {
	j.mux.RLock()
	defer j.mux.RUnlock()
	kids = make([]string, len(j.keys))
	index := 0
	for kid := range j.keys {
		kids[index] = kid
		index++
	}
	return kids
}

// Len returns the number of keys in the JWKS.
func (j *JWKS) Len() int {
	j.mux.RLock()
	defer j.mux.RUnlock()
	result := 0
	for _, val := range j.keys {
		result += len(val)
	}
	return result
}

// RawJWKS returns a copy of the raw JWKS received from the given JWKS URL.
func (j *JWKS) RawJWKS() []byte {
	j.mux.RLock()
	defer j.mux.RUnlock()
	raw := make([]byte, len(j.raw))
	copy(raw, j.raw)
	return raw
}

// ReadOnlyKeys returns a read-only copy of the mapping of key IDs (`kid`) to cryptographic keys.
// Currently this function is used for test purposes only
func (j *JWKS) ReadOnlyKeys() map[string]interface{} {
	keys := make(map[string]interface{})
	j.mux.Lock()
	for kid, parsedKey := range j.keys {
		// TODO: generalize this function to account for multiple keys with a given kid
		keys[kid] = parsedKey[0].Public
	}
	j.mux.Unlock()
	return keys
}

func (j *JWKS) canUseKey(key ParsedJWK) bool {
	canUseKey := true
	// jwkUseWhitelist might be empty if the jwks was from keyfunc.NewJSON() or if JWKUseNoWhitelist option was true.
	// in this case we don't restrict "use" parameter
	if len(j.jwkUseWhitelist) > 0 {
		_, canUseKey = j.jwkUseWhitelist[key.use]
	}
	return canUseKey
}

func checkSlicesIntersect(slice1 []string, slice2 []string) bool {
	for _, v1 := range slice1 {
		for _, v2 := range slice2 {
			if v1 == v2 {
				return true
			}
		}
	}
	return false
}

// GetTypeForAlg returns the corresponding Key Type (kty)
// for a given `alg` value.
// kty: https://www.rfc-editor.org/rfc/rfc7518#section-7.4.2
// alg: https://www.rfc-editor.org/rfc/rfc7518#section-7.1.2
func GetTypeForAlg(alg string) string {
	switch alg {
	case "RS256", "RS384", "RS512":
		return "RSA"
	case "ES384", "ES256", "ES512":
		return "EC"
	case "HS256", "HS384", "HS512":
		return "oct"
	case "EdDSA":
		return "OKP"
	}
	return ""
}

func (j *JWKS) filterKeys(alg string, token *jwt.Token, parsedKeys []ParsedJWK) []*ParsedJWK {
	var result []*ParsedJWK
	for idx, key := range parsedKeys {
		if (key.algorithm == alg || (key.algorithm == "" && GetTypeForAlg(alg) == key.kty)) && j.canUseKey(key) {
			audienceMatch := false
			// https://docs.singlestore.com/db/v7.8/en/security/authentication/authenticate-via-jwt.html#validate-jwts-with-jwks
			// If the matching JWK includes an aud (Audience) field which does not match the aud field in the JWT, then the authentication request is rejected.
			// The aud field can be a string or an array of strings. If any aud string of the JWT matches any aud string of the JWK, it is considered a match.
			if len(key.audience) == 0 {
				// If the matching JWK does not define an audience (aud), audience checking is skipped. Note that aud is not a standard field in JWK.
				audienceMatch = true
			} else {
				var audToken []string
				claims, ok := token.Claims.(jwt.MapClaims)
				if !ok {
					return result
				}
				audTokenInter, ok := claims["aud"]
				if ok {
					audTokenStr, ok := audTokenInter.(string)
					if ok {
						// audToken is a comma-separated string
						audToken = strings.Split(audTokenStr, ",")
					} else {
						// audToken is an array of strings
						audToken, _ = audTokenInter.([]string)
					}
					for idx := range audToken {
						audToken[idx] = strings.TrimSpace(audToken[idx])
					}
					// If any aud string of the JWT matches any aud string of the JWK, it is considered a match
					audienceMatch = checkSlicesIntersect(audToken, key.audience)
				}
			}
			if audienceMatch {
				result = append(result, &parsedKeys[idx])
			}
		}
	}
	return result
}

// GetMatchingKeys implements the logic described in
// https://docs.singlestore.com/db/v7.8/en/security/authentication/authenticate-via-jwt.html
// A Read Lock for `j.mux` is acquired when the JWKS is read
//
// JWTs are matched with JSON Web Keys (JWKs) for validation as follows:
// 1. If the JWT has a kid (Key ID) field, the JWKs with matching kid fields are validated.
// 2. If the JWT has a kid field that doesn’t match any JWK or jwt_config key, the authentication request is rejected. See Validate JWTs with the jwt-config for more information.
// 3. If the JWT has an iss (Issuer) field (instead of a kid field) that matches the kid in one or more JWKs, the JWKs with matching kid fields are validated.
// 4. If the JWT does not have a kid field and the iss field does not match the kid field in any JWK, then validation is attempted with all the JWKs with a matching alg (Algorithm) field. If the alg field is not specified, the kty (Key Type) field is used instead.
func (j *JWKS) GetMatchingKeys(token *jwt.Token) ([]*ParsedJWK, error) {
	var result []*ParsedJWK
	// alg must be present in jwt
	var alg string
	algInter, ok := token.Header["alg"]
	if ok {
		alg, ok = algInter.(string)
		if !ok {
			return result, fmt.Errorf("could not convert `alg` in JWT header to string")
		}
	} else {
		return result, fmt.Errorf("could not validate a JWT without `alg` in header")
	}

	var kid string
	kidInter, ok := token.Header["kid"]
	if ok {
		kid, ok = kidInter.(string)
		if !ok {
			return result, fmt.Errorf("could not convert `kid` in JWT header to string")
		}
	}

	j.mux.RLock()
	defer j.mux.RUnlock()
	if kid != "" {
		if parsedKeys, ok := j.keys[kid]; ok {
			result = j.filterKeys(alg, token, parsedKeys)
		}
		// when "kid" is present in JWT, we match only keys with the same kid
		return result, nil
	}
	var iss string
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return result, fmt.Errorf("cannot get claims from the token %s", token.Raw)
	}
	issInter, ok := claims["iss"]
	// iss is present in jwt
	if ok {
		iss, ok = issInter.(string)
		if !ok {
			return result, fmt.Errorf("could not convert `iss` in JWT header to string")
		}
	}
	if iss != "" {
		if parsedKeys, ok := j.keys[iss]; ok {
			result = j.filterKeys(alg, token, parsedKeys)
		}
	}
	// no "kid" and no match with "iss", use "alg" only
	if len(result) == 0 {
		for _, parsedKeys := range j.keys {
			currentResult := j.filterKeys(alg, token, parsedKeys)
			result = append(result, currentResult...)
		}
	}
	return result, nil
}

// GetMatchingKeysWithRefresh gets the keys according to SingleStore logic,
// and if `j.refreshUnknownKID` is set to `true`, performs jwks refresh if no key was matched
func (j *JWKS) GetMatchingKeysWithRefresh(token *jwt.Token) []*ParsedJWK {
	matchingKeys, _ := j.GetMatchingKeys(token)

	if len(matchingKeys) == 0 {
		if !j.refreshUnknownKID {
			return matchingKeys
		}

		ctx, cancel := context.WithCancel(j.ctx)

		// Refresh the JWKS.
		select {
		case <-j.ctx.Done():
			return matchingKeys
		case j.refreshRequests <- cancel:
		default:
			// If the j.refreshRequests channel is full, just return matchingKeys
			return matchingKeys
		}

		// Wait for the JWKS refresh to finish.
		<-ctx.Done()

		matchingKeys, _ = j.GetMatchingKeys(token)
	}
	return matchingKeys
}
