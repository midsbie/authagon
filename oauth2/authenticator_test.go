package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// Mock implementations for testing

type mockStateStore struct {
	authState AuthState
	setError  error
	getError  error
	delError  error
}

func (m *mockStateStore) Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (AuthState, error) {
	if m.setError != nil {
		return AuthState{}, m.setError
	}
	return m.authState, nil
}

func (m *mockStateStore) Get(r *http.Request) (AuthState, error) {
	if m.getError != nil {
		return AuthState{}, m.getError
	}
	return m.authState, nil
}

func (m *mockStateStore) Del(w http.ResponseWriter) error {
	return m.delError
}

type mockProvider struct {
	name         string
	config       oauth2.Config
	endpoints    endpoints
	profile      Profile
	extractError error
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Configure(conf *ServiceConfig) oauth2.Config {
	return m.config
}

func (m *mockProvider) Endpoints() endpoints {
	return m.endpoints
}

func (m *mockProvider) ExtractProfile(data ProfileMap, raw []byte) (Profile, error) {
	if m.extractError != nil {
		return Profile{}, m.extractError
	}
	return m.profile, nil
}

// Mock OAuth2 server for testing Complete method
func createMockOAuth2Server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			token := map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token)
		case "/profile":
			profile := map[string]interface{}{
				"id":    "12345",
				"name":  "Test User",
				"email": "test@example.com",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(profile)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAuthenticator_Start(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sessionError  error
		wantError     bool
		errorContains string
	}{
		{
			name:         "successful start",
			sessionError: nil,
			wantError:    false,
		},
		{
			name:          "session creation failure",
			sessionError:  fmt.Errorf("session store failed"),
			wantError:     true,
			errorContains: "failed to create authentication session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSession := &mockStateStore{
				authState: AuthState{
					State:       "test-state",
					Nonce:       "test-nonce",
					RedirectURL: "/dashboard",
				},
				setError: tt.sessionError,
			}

			mockProv := &mockProvider{
				name: "test-provider",
				config: oauth2.Config{
					ClientID: "test-client-id",
					Endpoint: oauth2.Endpoint{
						AuthURL: "https://example.com/auth",
					},
				},
			}

			auth := &authenticator{
				svcConf: &ServiceConfig{
					BaseURL: "https://myapp.com",
				},
				state:    mockSession,
				provider: mockProv,
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/login", nil)
			config := AuthConfig{
				RedirectURL: "/dashboard",
			}

			err := auth.Start(w, r, config)

			if tt.wantError {
				if err == nil {
					t.Fatalf("Start() error = nil, want error containing %q", tt.errorContains)
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Start() error = %q, want error containing %q", err.Error(), tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("Start() error = %v, want nil", err)
			}

			// Verify redirect response
			if w.Code != http.StatusFound {
				t.Errorf("Start() status = %d, want %d", w.Code, http.StatusFound)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, "https://example.com/auth") {
				t.Errorf("Start() redirect location = %q, want to contain auth URL", location)
			}
			if !strings.Contains(location, "state=test-state") {
				t.Errorf("Start() redirect location = %q, want to contain state parameter", location)
			}
		})
	}
}

func TestAuthenticator_Complete_Success(t *testing.T) {
	t.Parallel()

	// Create mock OAuth2 server
	server := createMockOAuth2Server()
	defer server.Close()

	mockSession := &mockStateStore{
		authState: AuthState{
			State:       "test-state",
			Nonce:       "test-nonce",
			RedirectURL: "/dashboard",
		},
	}

	expectedProfile := Profile{
		ID:   "12345",
		Name: "Test User",
	}

	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/auth",
				TokenURL: server.URL + "/token",
			},
		},
		endpoints: endpoints{
			ProfileURL: server.URL + "/profile",
		},
		profile: expectedProfile,
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	// Create request with callback parameters
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err != nil {
		t.Fatalf("Complete() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("Complete() result = nil, want non-nil")
	}

	if result.Provider != "test-provider" {
		t.Errorf("Complete() Provider = %q, want %q", result.Provider, "test-provider")
	}

	if result.Profile.ID != expectedProfile.ID {
		t.Errorf("Complete() Profile.ID = %q, want %q", result.Profile.ID, expectedProfile.ID)
	}

	if result.Profile.Name != expectedProfile.Name {
		t.Errorf("Complete() Profile.Name = %q, want %q", result.Profile.Name, expectedProfile.Name)
	}

	if result.RedirectURL != "/dashboard" {
		t.Errorf("Complete() RedirectURL = %q, want %q", result.RedirectURL, "/dashboard")
	}

	if result.Token.AccessToken != "mock-access-token" {
		t.Errorf("Complete() Token.AccessToken = %q, want %q", result.Token.AccessToken, "mock-access-token")
	}
}

func TestAuthenticator_Complete_MissingState(t *testing.T) {
	t.Parallel()

	auth := &authenticator{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code", nil)

	result, err := auth.Complete(w, r)
	if err != ErrStateMissing {
		t.Errorf("Complete() error = %v, want %v", err, ErrStateMissing)
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_SessionRetrievalError(t *testing.T) {
	t.Parallel()

	mockSession := &mockStateStore{
		getError: fmt.Errorf("session retrieval failed"),
	}

	auth := &authenticator{state: mockSession}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to retrieve authentication session") {
		t.Errorf("Complete() error = %q, want error containing session retrieval failure", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_StateStateMismatch(t *testing.T) {
	t.Parallel()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "expected-state",
		},
	}

	auth := &authenticator{state: mockSession}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=different-state", nil)

	result, err := auth.Complete(w, r)
	if err != ErrUnexpectedState {
		t.Errorf("Complete() error = %v, want %v", err, ErrUnexpectedState)
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_MissingCode(t *testing.T) {
	t.Parallel()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "test-state",
		},
	}

	auth := &authenticator{state: mockSession}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "code query parameter is missing") {
		t.Errorf("Complete() error = %q, want error about missing code", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_TokenExchangeFailure(t *testing.T) {
	t.Parallel()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "test-state",
		},
	}

	// Create mock provider with invalid token endpoint
	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://invalid-endpoint.example.com/token",
			},
		},
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "authentication exchance failed") {
		t.Errorf("Complete() error = %q, want error about exchange failure", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_ProfileFetchFailure(t *testing.T) {
	t.Parallel()

	// Create server that only handles token exchange, not profile
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token := map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "test-state",
		},
	}

	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		endpoints: endpoints{
			ProfileURL: "https://invalid-profile-url.example.com/profile",
		},
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to fetch profile") {
		t.Errorf("Complete() error = %q, want error about profile fetch failure", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_ProfileExtractionFailure(t *testing.T) {
	t.Parallel()

	server := createMockOAuth2Server()
	defer server.Close()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "test-state",
		},
	}

	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		endpoints: endpoints{
			ProfileURL: server.URL + "/profile",
		},
		extractError: fmt.Errorf("profile extraction failed"),
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to extract profile") {
		t.Errorf("Complete() error = %q, want error about profile extraction failure", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}

func TestAuthenticator_Complete_SessionDeletionFailure(t *testing.T) {
	t.Parallel()

	server := createMockOAuth2Server()
	defer server.Close()

	mockSession := &mockStateStore{
		authState: AuthState{
			State:       "test-state",
			RedirectURL: "/dashboard",
		},
		delError: fmt.Errorf("session deletion failed"),
	}

	expectedProfile := Profile{
		ID:   "12345",
		Name: "Test User",
	}

	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		endpoints: endpoints{
			ProfileURL: server.URL + "/profile",
		},
		profile: expectedProfile,
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	// Session deletion failure should not prevent successful completion
	result, err := auth.Complete(w, r)
	if err != nil {
		t.Fatalf("Complete() error = %v, want nil (session deletion failure should not fail completion)", err)
	}

	if result == nil {
		t.Fatal("Complete() result = nil, want non-nil")
	}

	if result.Provider != "test-provider" {
		t.Errorf("Complete() Provider = %q, want %q", result.Provider, "test-provider")
	}
}

func TestAuthenticator_Complete_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Create server that returns invalid JSON for profile
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			token := map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token)
		case "/profile":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json response"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	mockSession := &mockStateStore{
		authState: AuthState{
			State: "test-state",
		},
	}

	mockProv := &mockProvider{
		name: "test-provider",
		config: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		endpoints: endpoints{
			ProfileURL: server.URL + "/profile",
		},
	}

	auth := &authenticator{
		svcConf:  &ServiceConfig{BaseURL: "https://myapp.com"},
		state:    mockSession,
		provider: mockProv,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?code=test-code&state=test-state", nil)

	result, err := auth.Complete(w, r)
	if err == nil {
		t.Fatal("Complete() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to unmarshal profile") {
		t.Errorf("Complete() error = %q, want error about JSON unmarshaling", err.Error())
	}
	if result != nil {
		t.Errorf("Complete() result = %v, want nil", result)
	}
}
