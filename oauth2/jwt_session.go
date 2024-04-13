package oauth2

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/midsbie/authagon/store"
)

const (
	randomTokenLen    = 32
	defaultIssuer     = "authagon"
	defaultSessionKey = "auth_token"
	defaultDuration   = 15 * time.Minute
)

// Claims extends jwt.StandardClaims to include additional information specific to an OAuth
// handshake process. It encapsulates the standard JWT claims like issuer, subject, and expiration
// time, along with a Handshake field that contains OAuth-specific state information used during the
// authentication flow.
type Claims struct {
	jwt.StandardClaims
	Context *Context `json:"ctx,omitempty"`
}

// Context holds information used to maintain and validate state during the OAuth2 authentication
// process. It includes a state parameter to prevent CSRF attacks and a URL field which can be used
// to redirect the user after a successful authentication.
type Context struct {
	State       string `json:"ste"`
	RedirectURL string `json:"url"`
}

// JWTSession encapsulates configuration and state for managing JWT-based sessions in an OAuth2
// context. It includes a store for persisting session data, issuer and audience identifiers for
// token validation, cookie name and durations for HTTP cookie management, and a secret for signing
// JWTs. The struct is used to create, validate, and terminate sessions that rely on JWT for
// authentication and state management in web applications.
type JWTSession struct {
	store           store.BrowserStorer
	secret          string
	issuer          string
	audience        string
	sessionKey      string
	sessionDuration time.Duration
	tokenDuration   time.Duration
}

// option configures a JWTSession.
type option func(*JWTSession)

// WithJWTIssuer sets the issuer of the JWTSession.
func WithJWTIssuer(issuer string) option {
	return func(c *JWTSession) {
		c.issuer = issuer
	}
}

// WithAudience sets the audience of the JWTSession.
func WithAudience(audience string) option {
	return func(c *JWTSession) {
		c.audience = audience
	}
}

// WithSessionKey sets the cookie name of the JWTSession.
func WithSessionKey(name string) option {
	return func(c *JWTSession) {
		c.sessionKey = name
	}
}

// WithJWTSessionDuration sets the cookie duration of the JWTSession.
func WithJWTSessionDuration(duration time.Duration) option {
	return func(c *JWTSession) {
		c.sessionDuration = duration
	}
}

// WithTokenDuration sets the token duration of the JWTSession.
func WithTokenDuration(duration time.Duration) option {
	return func(c *JWTSession) {
		c.tokenDuration = duration
	}
}

// NewJWTSession initializes a new JWTSession with default configuration and applies any provided
// options for customization. This function creates a session manager designed for JWT-based
// authentication flows, allowing the caller to specify key parameters such as the token issuer,
// session storage key, session and token expiration durations, and the signing secret. The session
// manager is capable of creating, validating, and terminating sessions using JWTs for
// authentication and state management within web applications or other HTTP-based services.
//
// The constructor requires a store for persisting session data and a secret for signing the
// JWTs. Additional configurations can be applied through variadic option functions.
func NewJWTSession(store store.BrowserStorer, secret string, options ...option) (
	*JWTSession, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if secret == "" {
		return nil, fmt.Errorf("secret is required")
	}

	session := JWTSession{
		store:           store,
		secret:          secret,
		issuer:          defaultIssuer,
		sessionKey:      defaultSessionKey,
		sessionDuration: defaultDuration,
		tokenDuration:   defaultDuration,
	}

	for _, option := range options {
		option(&session)
	}

	return &session, nil
}

func (s *JWTSession) Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (
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
	claims := Claims{
		Context: &Context{
			State:       auth.State,
			RedirectURL: auth.RedirectURL,
		},
		StandardClaims: jwt.StandardClaims{
			Id:        auth.Nonce,
			Issuer:    s.issuer,
			Audience:  auth.Audience,
			ExpiresAt: now.Add(s.tokenDuration).Unix(),
			NotBefore: now.Unix(),
		},
	}

	claims.IssuedAt = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if tokenString, err := token.SignedString([]byte(s.secret)); err != nil {
		return AuthState{}, fmt.Errorf("failed to generate signed token string: %w", err)
	} else if err := s.store.Set(w, s.sessionKey, tokenString, s.sessionDuration); err != nil {
		return AuthState{}, err
	}

	return auth, nil
}

func (s *JWTSession) Get(r *http.Request) (AuthState, error) {
	tokenString, ok, err := s.store.Get(r, s.sessionKey)
	if err != nil {
		return AuthState{}, err
	} else if !ok {
		return AuthState{}, ErrUnauthenticated
	}

	parser := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Alg()}}
	token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (
		interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v",
				token.Header["alg"])
		}
		return []byte(s.secret), nil
	})
	if err != nil {
		return AuthState{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return AuthState{}, fmt.Errorf("invalid token")
	} else if claims.Context == nil {
		return AuthState{}, fmt.Errorf("context not found")
	} else if s.audience != "" && claims.Audience != s.audience {
		return AuthState{}, fmt.Errorf("audience not allowed: %s", claims.Audience)
	} else if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return AuthState{}, fmt.Errorf("token expired")
	}

	return AuthState{
		State:       claims.Context.State,
		Nonce:       claims.Id,
		Audience:    claims.Audience,
		RedirectURL: claims.Context.RedirectURL}, nil
}

func (s *JWTSession) Del(w http.ResponseWriter) error {
	return s.store.Del(w, s.sessionKey)
}
