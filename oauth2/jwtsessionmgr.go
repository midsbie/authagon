package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/midsbie/authagon/store"
)

const (
	randomTokenLen    = 32
	defaultIssuer     = "authagon"
	defaultSessionKey = "auth_token"
	defaultDuration   = 15 * time.Minute
)

// Claims extends jwt.RegisteredClaims with OAuth2/OIDC handshake state.
// It carries the usual JWT fields (issuer, subject, expiry, etc.) along with a Context field that
// holds the opaque state value and redirect URL used during the authentication flow.
type Claims struct {
	jwt.RegisteredClaims
	Context *Context `json:"ctx,omitempty"`
}

// Context holds information used to maintain and validate state during the OAuth2 authentication
// process. It includes a state parameter to prevent CSRF attacks and a URL field which can be used
// to redirect the user after a successful authentication.
type Context struct {
	State       string `json:"ste"`
	RedirectURL string `json:"url"`
}

// JWTStateStore manages short-lived OAuth2/OIDC handshake state using a signed JWT stored via a
// store.BrowserStorer. It encodes state, redirect URL, issuer, audience, and expiry into claims,
// and is not responsible for long-lived application sessions. It is a good fit when you want
// stateless handshake state with audience validation and cryptographic integrity without
// introducing additional server-side storage. For simpler setups, a StateStore backed by
// SessionStorer[AuthState] can be used instead.
type JWTStateStore struct {
	store           store.BrowserStorer
	secret          string
	issuer          string
	audience        string
	sessionKey      string
	sessionDuration time.Duration
	tokenDuration   time.Duration
}

// StateStoreOption configures a JWTStateStore.
type StateStoreOption func(*JWTStateStore)

// WithJWTIssuer sets the issuer claim of the JWTStateStore.
func WithJWTIssuer(issuer string) StateStoreOption {
	return func(c *JWTStateStore) {
		c.issuer = issuer
	}
}

// WithAudience sets the audience claim of the JWTStateStore.
func WithAudience(audience string) StateStoreOption {
	return func(c *JWTStateStore) {
		c.audience = audience
	}
}

// WithSessionKey sets the cookie name used to store the JWT.
func WithSessionKey(name string) StateStoreOption {
	return func(c *JWTStateStore) {
		c.sessionKey = name
	}
}

// WithJWTSessionDuration sets the cookie duration for the handshake JWT.
func WithJWTSessionDuration(duration time.Duration) StateStoreOption {
	return func(c *JWTStateStore) {
		c.sessionDuration = duration
	}
}

// WithTokenDuration sets the JWT expiry duration for the handshake token.
func WithTokenDuration(duration time.Duration) StateStoreOption {
	return func(c *JWTStateStore) {
		c.tokenDuration = duration
	}
}

// NewJWTStateStore initializes a new JWTStateStore with default configuration and applies any
// provided options for customization. It creates a StateStore implementation for short-lived
// OAuth2/OIDC handshake state, allowing the caller to specify token issuer, cookie key, session and
// token lifetimes, and the signing secret. The constructor requires a BrowserStorer for persisting
// the JWT and a non-empty secret. Additional configuration can be supplied via StateStoreOption
// values.
func NewJWTStateStore(store store.BrowserStorer, secret string, options ...StateStoreOption) (
	*JWTStateStore, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if secret == "" {
		return nil, fmt.Errorf("secret is required")
	}

	state := JWTStateStore{
		store:           store,
		secret:          secret,
		issuer:          defaultIssuer,
		sessionKey:      defaultSessionKey,
		sessionDuration: defaultDuration,
		tokenDuration:   defaultDuration,
	}

	for _, opt := range options {
		opt(&state)
	}

	return &state, nil
}

// Set creates a new AuthState for the given AuthConfig, signs it into a JWT, stores it in the
// underlying BrowserStorer, and returns the resulting state.  It generates a random state and nonce
// and encodes state, redirect URL, issuer, audience, and expiry into the token.
func (s *JWTStateStore) Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (
	AuthState, error) {
	state, err := RandomToken(randomTokenLen)
	if err != nil {
		return AuthState{}, fmt.Errorf("failed to generate oauth2 state: %w", err)
	}

	nonce, err := RandomToken(randomTokenLen)
	if err != nil {
		return AuthState{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	auth := AuthState{
		State:       state,
		Nonce:       nonce,
		Audience:    s.audience,
		RedirectURL: config.RedirectURL,
	}

	now := time.Now()
	var aud jwt.ClaimStrings
	if auth.Audience != "" {
		aud = jwt.ClaimStrings{auth.Audience}
	}
	claims := Claims{
		Context: &Context{
			State:       auth.State,
			RedirectURL: auth.RedirectURL,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        auth.Nonce,
			Issuer:    s.issuer,
			Audience:  aud,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if tokenString, err := token.SignedString([]byte(s.secret)); err != nil {
		return AuthState{}, fmt.Errorf("failed to generate signed token string: %w", err)
	} else if err := s.store.Set(w, s.sessionKey, tokenString, s.sessionDuration); err != nil {
		return AuthState{}, err
	}

	return auth, nil
}

// Get reads the handshake JWT from the underlying BrowserStorer, validates it, and returns the
// decoded AuthState. If the cookie is missing it returns ErrUnauthenticated. If the token is
// expired it returns ErrTokenExpired.  Other parsing or validation failures are returned as errors.
func (s *JWTStateStore) Get(r *http.Request) (AuthState, error) {
	tokenString, err := s.store.Get(r, s.sessionKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return AuthState{}, ErrUnauthenticated
		}

		return AuthState{}, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (
		any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v",
				token.Header["alg"])
		}
		return []byte(s.secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return AuthState{}, ErrTokenExpired
		}
		return AuthState{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return AuthState{}, fmt.Errorf("invalid token")
	} else if claims.Context == nil {
		return AuthState{}, fmt.Errorf("context not found")
	} else if s.audience != "" && !slices.Contains(claims.Audience, s.audience) {
		return AuthState{}, fmt.Errorf("audience not allowed: %v", claims.Audience)
	}

	var audience string
	if len(claims.Audience) > 0 {
		audience = claims.Audience[0]
	}

	return AuthState{
		State:       claims.Context.State,
		Nonce:       claims.ID,
		Audience:    audience,
		RedirectURL: claims.Context.RedirectURL}, nil
}

// Del removes the stored handshake JWT from the underlying BrowserStorer.
func (s *JWTStateStore) Del(w http.ResponseWriter) error {
	return s.store.Del(w, s.sessionKey)
}
