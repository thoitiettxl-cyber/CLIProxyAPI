package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRunCodexBrowserLoginUsesPKCEAndPiAuthorization(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	access := testJWT(t, map[string]any{
		"email": "person@example.com",
		openAIAuthClaimKey: map[string]any{
			"chatgpt_account_id": "acct-browser",
			"chatgpt_plan_type":  "plus",
		},
	})
	client := newFakeOAuthClient(t, func(request oauthHTTPRequest) oauthHTTPResponse {
		assertRequest(t, request, http.MethodPost, codexTokenURL, "application/x-www-form-urlencoded")
		form := parseRequestForm(t, request)
		if got := form.Get("code"); got != "browser-code" {
			t.Fatalf("code = %q, want browser-code", got)
		}
		if got := form.Get("redirect_uri"); got != codexRedirectURI {
			t.Fatalf("redirect_uri = %q, want %q", got, codexRedirectURI)
		}
		if got := form.Get("code_verifier"); got == "" {
			t.Fatal("code_verifier is empty")
		}
		return jsonResponse(t, http.StatusOK, oauthTokenResponse{
			AccessToken:  access,
			RefreshToken: "refresh-secret",
			ExpiresIn:    3600,
		})
	})
	waiter := &fakeCallbackWaiter{code: "browser-code"}
	var callbackState string
	var openedURL string
	runtimeConfig := testOAuthRuntime(client, now)
	runtimeConfig.random = bytes.NewReader(bytes.Repeat([]byte{0x4a}, 64))
	runtimeConfig.startCallback = func(state string, port int) (codexCallbackWaiter, error) {
		callbackState = state
		if port != 1455 {
			t.Fatalf("callback port = %d, want 1455", port)
		}
		return waiter, nil
	}
	runtimeConfig.openURL = func(rawURL string) error {
		openedURL = rawURL
		return nil
	}

	auth, err := runCodexBrowserLogin(context.Background(), false, runtimeConfig)
	if err != nil {
		t.Fatalf("runCodexBrowserLogin() error = %v", err)
	}
	client.assertDone()
	if callbackState == "" {
		t.Fatal("callback state is empty")
	}
	if !waiter.closed {
		t.Fatal("callback waiter was not closed")
	}
	parsed, errParse := url.Parse(openedURL)
	if errParse != nil {
		t.Fatalf("parse opened URL: %v", errParse)
	}
	if got := parsed.Query().Get("state"); got != callbackState {
		t.Fatalf("opened state = %q, want %q", got, callbackState)
	}
	if got := parsed.Query().Get("originator"); got != piIdentity {
		t.Fatalf("originator = %q, want pi", got)
	}
	assertPiIdentityMetadata(t, auth.Metadata, true)
}

func TestRunCodexDeviceLoginUsesExpectedEndpoints(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	access := testJWT(t, map[string]any{
		"email": "person@example.com",
		openAIAuthClaimKey: map[string]any{
			"chatgpt_account_id": "acct-device",
		},
	})
	client := newFakeOAuthClient(t,
		func(request oauthHTTPRequest) oauthHTTPResponse {
			assertRequest(t, request, http.MethodPost, codexDeviceUserCodeURL, "application/json")
			var body map[string]string
			if err := json.Unmarshal(request.Body, &body); err != nil {
				t.Fatalf("decode device request: %v", err)
			}
			if body["client_id"] != codexClientID {
				t.Fatalf("client_id = %q", body["client_id"])
			}
			return jsonResponse(t, http.StatusOK, map[string]any{
				"device_auth_id": "device-auth-1",
				"user_code":      "ABCD-EFGH",
				"interval":       1,
			})
		},
		func(request oauthHTTPRequest) oauthHTTPResponse {
			assertRequest(t, request, http.MethodPost, codexDeviceTokenURL, "application/json")
			var body map[string]string
			if err := json.Unmarshal(request.Body, &body); err != nil {
				t.Fatalf("decode poll request: %v", err)
			}
			if body["device_auth_id"] != "device-auth-1" || body["user_code"] != "ABCD-EFGH" {
				t.Fatalf("poll body = %#v", body)
			}
			return jsonResponse(t, http.StatusOK, map[string]string{
				"authorization_code": "authorization-code",
				"code_verifier":      "device-verifier",
			})
		},
		func(request oauthHTTPRequest) oauthHTTPResponse {
			assertRequest(t, request, http.MethodPost, codexTokenURL, "application/x-www-form-urlencoded")
			form := parseRequestForm(t, request)
			if got := form.Get("redirect_uri"); got != codexDeviceRedirectURI {
				t.Fatalf("redirect_uri = %q, want %q", got, codexDeviceRedirectURI)
			}
			if got := form.Get("code_verifier"); got != "device-verifier" {
				t.Fatalf("code_verifier = %q", got)
			}
			return jsonResponse(t, http.StatusOK, oauthTokenResponse{
				AccessToken:  access,
				RefreshToken: "refresh-secret",
				ExpiresIn:    3600,
			})
		},
	)
	runtimeConfig := testOAuthRuntime(client, now)
	var openedURL string
	runtimeConfig.openURL = func(rawURL string) error {
		openedURL = rawURL
		return nil
	}

	auth, err := runCodexDeviceLogin(context.Background(), false, runtimeConfig)
	if err != nil {
		t.Fatalf("runCodexDeviceLogin() error = %v", err)
	}
	client.assertDone()
	if openedURL != codexDeviceVerifyURL {
		t.Fatalf("opened URL = %q, want %q", openedURL, codexDeviceVerifyURL)
	}
	assertPiIdentityMetadata(t, auth.Metadata, true)
}

func TestRunXAIDeviceLoginUsesPiReferrerAndWaitsBeforePolling(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	idToken := testJWT(t, map[string]any{"email": "person@example.com", "sub": "person-1"})
	client := newFakeOAuthClient(t,
		func(request oauthHTTPRequest) oauthHTTPResponse {
			assertRequest(t, request, http.MethodPost, xaiDeviceCodeURL, "application/x-www-form-urlencoded")
			form := parseRequestForm(t, request)
			if got := form.Get("referrer"); got != piIdentity {
				t.Fatalf("referrer = %q, want pi", got)
			}
			return jsonResponse(t, http.StatusOK, map[string]any{
				"device_code":               "device-code",
				"user_code":                 "WXYZ-1234",
				"verification_uri":          "https://auth.x.ai/device",
				"verification_uri_complete": "https://auth.x.ai/device?user_code=WXYZ-1234",
				"expires_in":                900,
				"interval":                  2,
			})
		},
		func(request oauthHTTPRequest) oauthHTTPResponse {
			assertRequest(t, request, http.MethodPost, xaiTokenURL, "application/x-www-form-urlencoded")
			form := parseRequestForm(t, request)
			if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Fatalf("grant_type = %q", got)
			}
			if got := form.Get("device_code"); got != "device-code" {
				t.Fatalf("device_code = %q", got)
			}
			return jsonResponse(t, http.StatusOK, oauthTokenResponse{
				AccessToken:  "access-secret",
				RefreshToken: "refresh-secret",
				IDToken:      idToken,
				ExpiresIn:    3600,
			})
		},
	)
	runtimeConfig := testOAuthRuntime(client, now)
	var sleeps []time.Duration
	runtimeConfig.sleep = func(_ context.Context, duration time.Duration) error {
		sleeps = append(sleeps, duration)
		return nil
	}

	auth, err := runXAIDeviceLogin(context.Background(), true, runtimeConfig)
	if err != nil {
		t.Fatalf("runXAIDeviceLogin() error = %v", err)
	}
	client.assertDone()
	if len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("sleeps = %v, want [2s]", sleeps)
	}
	assertPiIdentityMetadata(t, auth.Metadata, false)
	if _, exists := auth.Metadata["using_api"]; exists {
		t.Fatal("using_api must remain unset")
	}
}

func TestPollDeviceFlowHonorsSlowDownIntervals(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	var sleeps []time.Duration
	runtimeConfig := oauthRuntime{
		now: func() time.Time { return now },
		sleep: func(_ context.Context, duration time.Duration) error {
			sleeps = append(sleeps, duration)
			return nil
		},
	}
	results := []devicePollResult{
		{status: devicePollSlowDown},
		{status: devicePollSlowDown, intervalSeconds: 2},
		completedPoll(oauthTokenResponse{AccessToken: "access"}),
	}
	index := 0
	_, err := pollDeviceFlow(context.Background(), -1, 60, false, runtimeConfig, func() devicePollResult {
		result := results[index]
		index++
		return result
	})
	if err != nil {
		t.Fatalf("pollDeviceFlow() error = %v", err)
	}
	want := []time.Duration{10 * time.Second, 2 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	for index := range want {
		if sleeps[index] != want[index] {
			t.Fatalf("sleeps[%d] = %s, want %s", index, sleeps[index], want[index])
		}
	}
}

func TestNormalizedPollIntervalDefaultsAndEnforcesMinimum(t *testing.T) {
	if got := normalizedPollInterval(0); got != time.Second {
		t.Fatalf("normalizedPollInterval(0) = %s", got)
	}
	if got := normalizedPollInterval(-1); got != 5*time.Second {
		t.Fatalf("normalizedPollInterval(-1) = %s", got)
	}
	if got := normalizedPollInterval(1); got != time.Second {
		t.Fatalf("normalizedPollInterval(1) = %s", got)
	}
}

func testOAuthRuntime(client oauthHTTPClient, now time.Time) oauthRuntime {
	return oauthRuntime{
		client:    client,
		now:       func() time.Time { return now },
		sleep:     func(context.Context, time.Duration) error { return nil },
		notify:    func(string) {},
		openURL:   func(string) error { return nil },
		userAgent: "pi (linux test; arm64)",
	}
}

type fakeOAuthClient struct {
	t        *testing.T
	handlers []func(oauthHTTPRequest) oauthHTTPResponse
	index    int
}

func newFakeOAuthClient(t *testing.T, handlers ...func(oauthHTTPRequest) oauthHTTPResponse) *fakeOAuthClient {
	t.Helper()
	return &fakeOAuthClient{t: t, handlers: handlers}
}

func (client *fakeOAuthClient) Do(request oauthHTTPRequest) (oauthHTTPResponse, error) {
	client.t.Helper()
	if client.index >= len(client.handlers) {
		client.t.Fatalf("unexpected OAuth HTTP request %s %s", request.Method, request.URL)
	}
	handler := client.handlers[client.index]
	client.index++
	return handler(request), nil
}

func (client *fakeOAuthClient) assertDone() {
	client.t.Helper()
	if client.index != len(client.handlers) {
		client.t.Fatalf("OAuth HTTP requests = %d, want %d", client.index, len(client.handlers))
	}
}

type fakeCallbackWaiter struct {
	code   string
	err    error
	closed bool
}

func (waiter *fakeCallbackWaiter) Wait(context.Context) (string, error) {
	return waiter.code, waiter.err
}

func (waiter *fakeCallbackWaiter) Close() error {
	waiter.closed = true
	return nil
}

func assertRequest(t *testing.T, request oauthHTTPRequest, method, rawURL, contentType string) {
	t.Helper()
	if request.Method != method || request.URL != rawURL {
		t.Fatalf("request = %s %s, want %s %s", request.Method, request.URL, method, rawURL)
	}
	if got := request.Header.Get("Content-Type"); got != contentType {
		t.Fatalf("Content-Type = %q, want %q", got, contentType)
	}
}

func parseRequestForm(t *testing.T, request oauthHTTPRequest) url.Values {
	t.Helper()
	form, err := url.ParseQuery(string(request.Body))
	if err != nil {
		t.Fatalf("parse request form: %v", err)
	}
	return form
}

func jsonResponse(t *testing.T, status int, value any) oauthHTTPResponse {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return oauthHTTPResponse{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       body,
	}
}

func TestSafeOAuthErrorDoesNotEchoArbitraryBody(t *testing.T) {
	response := oauthHTTPResponse{
		StatusCode: http.StatusBadRequest,
		Body:       []byte(`{"access_token":"must-not-appear"}`),
	}
	err := requireHTTPSuccess("token exchange", response)
	if err == nil {
		t.Fatal("requireHTTPSuccess() error = nil")
	}
	if strings.Contains(err.Error(), "must-not-appear") {
		t.Fatalf("error leaked response body: %v", err)
	}
}

func TestClassifyPendingResponseRecognizesNestedCodexError(t *testing.T) {
	response := oauthHTTPResponse{
		StatusCode: http.StatusBadRequest,
		Header:     make(http.Header),
		Body:       []byte(`{"error":{"code":"deviceauth_authorization_pending"}}`),
	}
	result := classifyPendingResponse("Codex device authorization", response)
	if result.status != devicePollPending {
		t.Fatalf("poll status = %d, want pending", result.status)
	}
}

func TestOAuthIntervalAcceptsCodexStringAndRejectsMalformedValues(t *testing.T) {
	var payload struct {
		Interval oauthInterval `json:"interval"`
	}
	if err := json.Unmarshal([]byte(`{"interval":"0.25"}`), &payload); err != nil {
		t.Fatalf("decode string interval: %v", err)
	}
	if !payload.Interval.Set || !payload.Interval.Valid || payload.Interval.Seconds != 0.25 {
		t.Fatalf("string interval = %#v", payload.Interval)
	}
	if got := normalizedPollInterval(payload.Interval.Seconds); got != time.Second {
		t.Fatalf("normalized 0.25 second interval = %s, want 1s", got)
	}
	if err := json.Unmarshal([]byte(`{"interval":"invalid"}`), &payload); err != nil {
		t.Fatalf("decode malformed interval: %v", err)
	}
	if !payload.Interval.Set || payload.Interval.Valid {
		t.Fatalf("malformed interval = %#v", payload.Interval)
	}
}

func TestDecodeTokenResponseExpiryRules(t *testing.T) {
	withoutExpiry := []byte(`{"access_token":"access","refresh_token":"refresh"}`)
	if _, err := decodeTokenResponse("Codex token exchange", withoutExpiry, true); err == nil {
		t.Fatal("required Codex expires_in error = nil")
	}
	xaiToken, err := decodeTokenResponse("xAI token response", withoutExpiry, false)
	if err != nil {
		t.Fatalf("optional xAI expires_in error = %v", err)
	}
	if xaiToken.ExpiresIn != 3600 {
		t.Fatalf("xAI default ExpiresIn = %d, want 3600", xaiToken.ExpiresIn)
	}
	negativeExpiry := []byte(`{"access_token":"access","refresh_token":"refresh","expires_in":-1}`)
	if _, err := decodeTokenResponse("xAI token response", negativeExpiry, false); err == nil {
		t.Fatal("negative xAI expires_in error = nil")
	}
}
