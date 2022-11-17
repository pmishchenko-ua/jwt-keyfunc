package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
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
	Algorithm   string      `json:"alg"`
	Curve       string      `json:"crv"`
	Exponent    string      `json:"e"`
	K           string      `json:"k"`
	ID          string      `json:"kid"`
	Modulus     string      `json:"n"`
	Type        string      `json:"kty"`
	Use         string      `json:"use"`
	X           string      `json:"x"`
	Y           string      `json:"y"`
	UserNameKey string      `json:"usernameFrom"`
	Audience    interface{} `json:"aud"`
}

// parsedJWK represents a JSON Web Key parsed with fields as the correct Go types.
type ParsedJWK struct {
	algorithm string
	Public    interface{}
	use       JWKUse
	Jwk       *JsonWebKey
	kid       string
	Audience  []string
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
	keys                []ParsedJWK
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     time.Duration
	refreshRateLimit    time.Duration
	refreshRequests     chan context.CancelFunc
	refreshTimeout      time.Duration
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
		keys: make([]ParsedJWK, len(rawKS.Keys)),
	}
	for idx, key := range rawKS.Keys {
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

		jwks.keys[idx] = ParsedJWK{
			algorithm: key.Algorithm,
			use:       JWKUse(key.Use),
			Public:    keyInter,
			Jwk:       key,
			kid:       key.ID,
			Audience:  audience,
		}
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
	for idx, key := range j.keys {
		kids[idx] = key.kid
	}
	return kids
}

// Len returns the number of keys in the JWKS.
func (j *JWKS) Len() int {
	j.mux.RLock()
	defer j.mux.RUnlock()
	return len(j.keys)
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
func (j *JWKS) ReadOnlyKeys() map[string]interface{} {
	keys := make(map[string]interface{})
	j.mux.Lock()
	for _, key := range j.keys {
		keys[key.kid] = key.Public
	}
	j.mux.Unlock()
	return keys
}
func findKeyIdx(alg string, kid string, keys []ParsedJWK) int {
	for idx, key := range keys {
		if key.kid == kid {
			return idx
		}
	}
	return -1
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

func (j *JWKS) getMatchingKeys(alg, kid, iss string) []*ParsedJWK {
	result := make([]*ParsedJWK, 0, 1)
	if kid != "" {
		for idx, key := range j.keys {
			if (key.kid == kid) && (key.algorithm == alg || key.algorithm == "") && j.canUseKey(key) {
					result = append(result, &j.keys[idx])
			}
		}
		return result
	}
	if iss != "" {
		for _, key := range j.keys {
			if key.kid == iss && (key.algorithm == alg || key.algorithm == "") && j.canUseKey(key) {
				result = append(result, &key)
			}
		}
	}
	// no match with "iss", use "alg" only
	if len(result) == 0 {
		for idx, key := range j.keys {
			if key.algorithm == alg || key.algorithm == "" {
				// jwkUseWhitelist might be empty if the jwks was from keyfunc.NewJSON() or if JWKUseNoWhitelist option was true.
				canUseKey := true
				if len(j.jwkUseWhitelist) > 0 {
					_, canUseKey = j.jwkUseWhitelist[j.keys[idx].use]
				}
				if canUseKey {
					result = append(result, &j.keys[idx])
				}
			}
		}
	}
	return result
}

// GetMatchingKeysWithRefresh implements the logic described in
// https://docs.singlestore.com/db/v7.8/en/security/authentication/authenticate-via-jwt.html
//
// JWTs are matched with JSON Web Keys (JWKs) for validation as follows:
//
// 1. If the JWT has a kid (Key ID) field, the JWKs with matching kid fields are validated.
// 2. If the JWT has a kid field that doesn’t match any JWK or jwt_config key, the authentication request is rejected. See Validate JWTs with the jwt-config for more information.
// 3. If the JWT has an iss (Issuer) field (instead of a kid field) that matches the kid in one or more JWKs, the JWKs with matching kid fields are validated.
// 4. If the JWT does not have a kid field and the iss field does not match the kid field in any JWK, then validation is attempted with all the JWKs with a matching alg (Algorithm) field. If the alg field is not specified, the kty (Key Type) field is used instead.
//
func (j *JWKS) GetMatchingKeysWithRefresh(alg, kid, iss string) (matchingKeys []*ParsedJWK, err error) {
	j.mux.RLock()
	matchingKeys = j.getMatchingKeys(alg, kid, iss)
	j.mux.RUnlock()

	if len(matchingKeys) == 0 {
		if !j.refreshUnknownKID {
			return matchingKeys, ErrNoMatchingKey
		}

		ctx, cancel := context.WithCancel(j.ctx)

		// Refresh the JWKS.
		select {
		case <-j.ctx.Done():
			return
		case j.refreshRequests <- cancel:
		default:
			// If the j.refreshRequests channel is full, return the error early.
			return matchingKeys, ErrNoMatchingKey
		}

		// Wait for the JWKS refresh to finish.
		<-ctx.Done()

		j.mux.RLock()
		defer j.mux.RUnlock()
		matchingKeys = j.getMatchingKeys(alg, kid, iss)
	}

	if len(matchingKeys) == 0 {
		return matchingKeys, ErrNoMatchingKey
	}

	return matchingKeys, nil
}
