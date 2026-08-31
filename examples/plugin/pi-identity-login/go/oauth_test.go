package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildCodexAuthorizationURLUsesPiIdentity(t *testing.T) {
	rawURL, err := buildCodexAuthorizationURL("state-1", "challenge-1")
	if err != nil {
		t.Fatalf("buildCodexAuthorizationURL() error = %v", err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	query := parsed.Query()
	want := map[string]string{
		"response_type":              "code",
		"client_id":                  codexClientID,
		"redirect_uri":               codexRedirectURI,
		"scope":                      codexScope,
		"code_challenge":             "challenge-1",
		"code_challenge_method":      "S256",
		"state":                      "state-1",
		"id_token_add_organizations": "true",
		"codex_cli_simplified_flow":  "true",
		"originator":                 piIdentity,
	}
	for key, wantValue := range want {
		if got := query.Get(key); got != wantValue {
			t.Errorf("query %s = %q, want %q", key, got, wantValue)
		}
	}
	if query.Has("prompt") {
		t.Fatalf("authorization URL unexpectedly contains prompt=%q", query.Get("prompt"))
	}
}

func TestXAIDeviceCodeFormUsesPiReferrer(t *testing.T) {
	form := xaiDeviceCodeForm()
	if got := form.Get("client_id"); got != xaiClientID {
		t.Fatalf("client_id = %q, want %q", got, xaiClientID)
	}
	if got := form.Get("scope"); got != xaiScope {
		t.Fatalf("scope = %q, want %q", got, xaiScope)
	}
	if got := form.Get("referrer"); got != piIdentity {
		t.Fatalf("referrer = %q, want %q", got, piIdentity)
	}
}

func TestFormatPiUserAgentMatchesPiShape(t *testing.T) {
	if got := formatPiUserAgent("linux", "6.12.0-test", "arm64"); got != "pi (linux 6.12.0-test; arm64)" {
		t.Fatalf("formatPiUserAgent() = %q", got)
	}
	if got := formatPiUserAgent("windows", "11", "amd64"); got != "pi (win32 11; x64)" {
		t.Fatalf("Windows formatPiUserAgent() = %q", got)
	}
}

func TestBuildCodexAuthDataPersistsPiIdentity(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	access := testJWT(t, map[string]any{
		"email": "person@example.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-123",
			"chatgpt_plan_type":  "pro",
		},
	})
	idToken := testJWT(t, map[string]any{"email": "person@example.com"})

	auth, err := buildCodexAuthData(oauthTokenResponse{
		AccessToken:  access,
		RefreshToken: "refresh-secret",
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, now, "pi (linux test; arm64)")
	if err != nil {
		t.Fatalf("buildCodexAuthData() error = %v", err)
	}
	if auth.Provider != "codex" {
		t.Fatalf("Provider = %q, want codex", auth.Provider)
	}
	if auth.ID != auth.FileName || !strings.HasPrefix(auth.FileName, "codex-pi-") {
		t.Fatalf("ID/FileName = %q/%q, want codex-pi filename", auth.ID, auth.FileName)
	}
	assertPiIdentityMetadata(t, auth.Metadata, true)
	if got := auth.Metadata["account_id"]; got != "acct-123" {
		t.Fatalf("account_id = %#v, want acct-123", got)
	}
	if got := auth.Attributes["plan_type"]; got != "pro" {
		t.Fatalf("plan_type attribute = %q, want pro", got)
	}
	if got := auth.Metadata["expired"]; got != now.Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("expired = %#v", got)
	}
}

func TestBuildXAIAuthDataPersistsPiIdentityWithoutChangingRoutingMode(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	idToken := testJWT(t, map[string]any{"email": "person@example.com", "sub": "user-123"})

	auth, err := buildXAIAuthData(oauthTokenResponse{
		AccessToken:  "access-secret",
		RefreshToken: "refresh-secret",
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, xaiTokenURL, now, "pi (linux test; arm64)")
	if err != nil {
		t.Fatalf("buildXAIAuthData() error = %v", err)
	}
	if auth.Provider != "xai" {
		t.Fatalf("Provider = %q, want xai", auth.Provider)
	}
	if auth.ID != auth.FileName || !strings.HasPrefix(auth.FileName, "xai-pi-") {
		t.Fatalf("ID/FileName = %q/%q, want xai-pi filename", auth.ID, auth.FileName)
	}
	assertPiIdentityMetadata(t, auth.Metadata, false)
	if _, exists := auth.Metadata["using_api"]; exists {
		t.Fatal("using_api must remain unset so built-in xAI OAuth routing is unchanged")
	}
	if got := auth.Metadata["auth_kind"]; got != "oauth" {
		t.Fatalf("auth_kind = %#v, want oauth", got)
	}
	if got := auth.Metadata["token_endpoint"]; got != xaiTokenURL {
		t.Fatalf("token_endpoint = %#v, want %q", got, xaiTokenURL)
	}
}

func TestNormalizeLoginModeRejectsUnknownValues(t *testing.T) {
	for _, value := range []string{"codex", "codex-device", "xai"} {
		if got, err := normalizeLoginMode(value); err != nil || got != value {
			t.Fatalf("normalizeLoginMode(%q) = %q, %v", value, got, err)
		}
	}
	if _, err := normalizeLoginMode("codex-default"); err == nil {
		t.Fatal("normalizeLoginMode(unknown) error = nil")
	}
}

func TestValidateVerificationURLRequiresHTTPS(t *testing.T) {
	if got, err := validateVerificationURL("https://auth.x.ai/device"); err != nil || got != "https://auth.x.ai/device" {
		t.Fatalf("validateVerificationURL(https) = %q, %v", got, err)
	}
	if _, err := validateVerificationURL("file:///tmp/token"); err == nil {
		t.Fatal("validateVerificationURL(file) error = nil")
	}
}

func assertPiIdentityMetadata(t *testing.T, metadata map[string]any, wantCodexPolicy bool) {
	t.Helper()
	if got := metadata["login_identity"]; got != piIdentity {
		t.Fatalf("login_identity = %#v, want pi", got)
	}
	headers, ok := metadata["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers type = %T, want map[string]any", metadata["headers"])
	}
	if got := headers["Originator"]; got != piIdentity {
		t.Fatalf("Originator = %#v, want pi", got)
	}
	if got := headers["User-Agent"]; got != "pi (linux test; arm64)" {
		t.Fatalf("User-Agent = %#v", got)
	}
	gotPolicy, exists := metadata[codexPreserveClientIdentityKey]
	if wantCodexPolicy {
		if !exists || gotPolicy != true {
			t.Fatalf("%s = %#v, want true", codexPreserveClientIdentityKey, gotPolicy)
		}
	} else if exists {
		t.Fatalf("xAI metadata unexpectedly contains %s", codexPreserveClientIdentityKey)
	}
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestPiCredentialFileNamesDoNotMatchNativeLoginNames(t *testing.T) {
	email := "person@example.com"
	pluginCodex := codexCredentialFileName(email, "plus", "acct-123")
	if !strings.HasPrefix(pluginCodex, "codex-pi-") {
		t.Fatalf("Codex plugin filename = %q, want codex-pi prefix", pluginCodex)
	}
	for _, native := range []string{
		"codex-" + email + ".json",
		"codex-" + email + "-plus.json",
		"codex-acct-123-" + email + ".json",
		"codex-acct-123-" + email + "-plus.json",
	} {
		if pluginCodex == native {
			t.Fatalf("Codex plugin filename collided with native %q", native)
		}
	}

	pluginXAI := xaiCredentialFileName(email, "user-123", time.Unix(0, 0).UTC())
	if !strings.HasPrefix(pluginXAI, "xai-pi-") {
		t.Fatalf("xAI plugin filename = %q, want xai-pi prefix", pluginXAI)
	}
	for _, native := range []string{
		"xai-" + email + ".json",
		"xai-user-123.json",
		"xai-pi-" + email + ".json",
	} {
		if pluginXAI == native {
			t.Fatalf("xAI plugin filename collided with native %q", native)
		}
	}
}
