package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPollInterval = 5 * time.Second
	minimumPollInterval = time.Second
	slowDownIncrement   = 5 * time.Second
	defaultFlowLifetime = 15 * time.Minute
)

type oauthHTTPRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type oauthHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type oauthInterval struct {
	Seconds float64
	Set     bool
	Valid   bool
}

func (interval *oauthInterval) UnmarshalJSON(raw []byte) error {
	interval.Set = true
	interval.Valid = false
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if errDecode := decoder.Decode(&value); errDecode != nil {
		return nil
	}
	parsed, ok := oauthSeconds(value)
	if !ok {
		return nil
	}
	interval.Seconds = parsed
	interval.Valid = true
	return nil
}

func oauthSeconds(value any) (float64, bool) {
	var seconds float64
	var errParse error
	switch typed := value.(type) {
	case json.Number:
		seconds, errParse = typed.Float64()
	case string:
		seconds, errParse = strconv.ParseFloat(strings.TrimSpace(typed), 64)
	case float64:
		seconds = typed
	case float32:
		seconds = float64(typed)
	case int:
		seconds = float64(typed)
	case int64:
		seconds = float64(typed)
	default:
		return 0, false
	}
	if errParse != nil || !isFinite(seconds) {
		return 0, false
	}
	return seconds, true
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validOAuthInterval(interval oauthInterval) float64 {
	if !interval.Set || !interval.Valid || interval.Seconds <= 0 {
		return 0
	}
	return interval.Seconds
}

func durationFromSeconds(seconds float64) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if seconds <= 0 {
		return 0
	}
	if seconds >= float64(maxDuration)/float64(time.Second) {
		return maxDuration
	}
	return time.Duration(math.Floor(seconds * float64(time.Second)))
}

func decodeOAuthError(body []byte) (code, description string, interval oauthInterval) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var payload map[string]any
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return "", "", oauthInterval{}
	}
	if value, exists := payload["interval"]; exists {
		interval.Set = true
		interval.Seconds, interval.Valid = oauthSeconds(value)
	}
	description, _ = payload["error_description"].(string)
	switch oauthError := payload["error"].(type) {
	case string:
		code = oauthError
	case map[string]any:
		code = firstNonEmpty(stringValue(oauthError["code"]), stringValue(oauthError["type"]))
		description = firstNonEmpty(description, stringValue(oauthError["message"]), stringValue(oauthError["description"]))
	}
	return strings.TrimSpace(code), strings.TrimSpace(description), interval
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

type oauthHTTPClient interface {
	Do(oauthHTTPRequest) (oauthHTTPResponse, error)
}

type codexCallbackWaiter interface {
	Wait(context.Context) (string, error)
	Close() error
}

type oauthRuntime struct {
	client        oauthHTTPClient
	random        io.Reader
	now           func() time.Time
	sleep         func(context.Context, time.Duration) error
	notify        func(string)
	openURL       func(string) error
	startCallback func(string, int) (codexCallbackWaiter, error)
	callbackPort  int
	userAgent     string
}

func (runtimeConfig oauthRuntime) withDefaults() oauthRuntime {
	if runtimeConfig.random == nil {
		runtimeConfig.random = rand.Reader
	}
	if runtimeConfig.now == nil {
		runtimeConfig.now = time.Now
	}
	if runtimeConfig.sleep == nil {
		runtimeConfig.sleep = sleepWithContext
	}
	if runtimeConfig.notify == nil {
		runtimeConfig.notify = func(string) {}
	}
	if runtimeConfig.openURL == nil {
		runtimeConfig.openURL = func(string) error { return nil }
	}
	if runtimeConfig.startCallback == nil {
		runtimeConfig.startCallback = startLocalCodexCallback
	}
	if runtimeConfig.callbackPort == 0 {
		runtimeConfig.callbackPort = 1455
	}
	if strings.TrimSpace(runtimeConfig.userAgent) == "" {
		runtimeConfig.userAgent = currentPiUserAgent()
	}
	return runtimeConfig
}

func loginWithPi(ctx context.Context, mode string, noBrowser bool, runtimeConfig oauthRuntime) (authData, error) {
	mode, errMode := normalizeLoginMode(mode)
	if errMode != nil {
		return authData{}, errMode
	}
	runtimeConfig = runtimeConfig.withDefaults()
	if runtimeConfig.client == nil {
		return authData{}, fmt.Errorf("OAuth HTTP client is unavailable")
	}
	switch mode {
	case "codex":
		return runCodexBrowserLogin(ctx, noBrowser, runtimeConfig)
	case "codex-device":
		return runCodexDeviceLogin(ctx, noBrowser, runtimeConfig)
	case "xai":
		return runXAIDeviceLogin(ctx, noBrowser, runtimeConfig)
	default:
		return authData{}, fmt.Errorf("unsupported Pi login mode %q", mode)
	}
}

func runCodexBrowserLogin(ctx context.Context, noBrowser bool, runtimeConfig oauthRuntime) (authData, error) {
	runtimeConfig = runtimeConfig.withDefaults()
	verifier, challenge, errPKCE := generatePKCE(runtimeConfig.random)
	if errPKCE != nil {
		return authData{}, errPKCE
	}
	state, errState := randomURLSafe(runtimeConfig.random, 24)
	if errState != nil {
		return authData{}, fmt.Errorf("generate Codex OAuth state: %w", errState)
	}
	redirectURI, errRedirect := codexCallbackRedirectURI(runtimeConfig.callbackPort)
	if errRedirect != nil {
		return authData{}, errRedirect
	}
	waiter, errListen := runtimeConfig.startCallback(state, runtimeConfig.callbackPort)
	if errListen != nil {
		return authData{}, fmt.Errorf("start Codex OAuth callback: %w", errListen)
	}
	defer func() {
		if errClose := waiter.Close(); errClose != nil {
			runtimeConfig.notify("Could not close the Codex OAuth callback listener.")
		}
	}()

	authorizeURL, errURL := buildCodexAuthorizationURLWithRedirect(state, challenge, redirectURI)
	if errURL != nil {
		return authData{}, errURL
	}
	runtimeConfig.notify("Open this URL to authenticate Codex with Pi identity:\n" + authorizeURL)
	openLoginURL(noBrowser, authorizeURL, runtimeConfig)

	code, errCode := waiter.Wait(ctx)
	if errCode != nil {
		return authData{}, errCode
	}
	token, errToken := exchangeCodexAuthorizationCode(runtimeConfig.client, code, verifier, redirectURI)
	if errToken != nil {
		return authData{}, errToken
	}
	return buildCodexAuthData(token, runtimeConfig.now(), runtimeConfig.userAgent)
}

func runCodexDeviceLogin(ctx context.Context, noBrowser bool, runtimeConfig oauthRuntime) (authData, error) {
	runtimeConfig = runtimeConfig.withDefaults()
	requestBody, errMarshal := json.Marshal(map[string]string{"client_id": codexClientID})
	if errMarshal != nil {
		return authData{}, fmt.Errorf("encode Codex device authorization request: %w", errMarshal)
	}
	response, errRequest := runtimeConfig.client.Do(jsonRequest(http.MethodPost, codexDeviceUserCodeURL, requestBody))
	if errRequest != nil {
		return authData{}, fmt.Errorf("request Codex device authorization: %w", errRequest)
	}
	if errStatus := requireHTTPSuccess("Codex device authorization", response); errStatus != nil {
		return authData{}, errStatus
	}
	var device struct {
		DeviceAuthID string        `json:"device_auth_id"`
		UserCode     string        `json:"user_code"`
		Interval     oauthInterval `json:"interval"`
	}
	if errDecode := json.Unmarshal(response.Body, &device); errDecode != nil {
		return authData{}, fmt.Errorf("decode Codex device authorization response: %w", errDecode)
	}
	device.DeviceAuthID = strings.TrimSpace(device.DeviceAuthID)
	device.UserCode = strings.TrimSpace(device.UserCode)
	if device.DeviceAuthID == "" || device.UserCode == "" || !device.Interval.Set || !device.Interval.Valid || device.Interval.Seconds < 0 {
		return authData{}, fmt.Errorf("Codex device authorization response is missing required fields")
	}

	runtimeConfig.notify(fmt.Sprintf("Open %s and enter code %s", codexDeviceVerifyURL, device.UserCode))
	openLoginURL(noBrowser, codexDeviceVerifyURL, runtimeConfig)
	token, errPoll := pollDeviceFlow(ctx, device.Interval.Seconds, defaultFlowLifetime.Seconds(), false, runtimeConfig, func() devicePollResult {
		return pollCodexDevice(runtimeConfig.client, device.DeviceAuthID, device.UserCode)
	})
	if errPoll != nil {
		return authData{}, fmt.Errorf("Codex device login: %w", errPoll)
	}
	return buildCodexAuthData(token, runtimeConfig.now(), runtimeConfig.userAgent)
}

func pollCodexDevice(client oauthHTTPClient, deviceAuthID, userCode string) devicePollResult {
	requestBody, errMarshal := json.Marshal(map[string]string{
		"device_auth_id": deviceAuthID,
		"user_code":      userCode,
	})
	if errMarshal != nil {
		return failedPoll(fmt.Errorf("encode Codex device poll request: %w", errMarshal))
	}
	response, errRequest := client.Do(jsonRequest(http.MethodPost, codexDeviceTokenURL, requestBody))
	if errRequest != nil {
		return failedPoll(fmt.Errorf("poll Codex device authorization: %w", errRequest))
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		var authorization struct {
			AuthorizationCode string `json:"authorization_code"`
			CodeVerifier      string `json:"code_verifier"`
		}
		if errDecode := json.Unmarshal(response.Body, &authorization); errDecode != nil {
			return failedPoll(fmt.Errorf("decode Codex device authorization result: %w", errDecode))
		}
		if strings.TrimSpace(authorization.AuthorizationCode) == "" || strings.TrimSpace(authorization.CodeVerifier) == "" {
			return failedPoll(fmt.Errorf("Codex device authorization result is missing required fields"))
		}
		token, errToken := exchangeCodexAuthorizationCode(client, authorization.AuthorizationCode, authorization.CodeVerifier, codexDeviceRedirectURI)
		if errToken != nil {
			return failedPoll(errToken)
		}
		return completedPoll(token)
	}
	return classifyPendingResponse("Codex device authorization", response)
}

func exchangeCodexAuthorizationCode(client oauthHTTPClient, code, verifier, redirectURI string) (oauthTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {codexClientID},
		"code":          {strings.TrimSpace(code)},
		"code_verifier": {strings.TrimSpace(verifier)},
		"redirect_uri":  {redirectURI},
	}
	response, errRequest := client.Do(formRequest(http.MethodPost, codexTokenURL, form))
	if errRequest != nil {
		return oauthTokenResponse{}, fmt.Errorf("exchange Codex authorization code: %w", errRequest)
	}
	if errStatus := requireHTTPSuccess("Codex token exchange", response); errStatus != nil {
		return oauthTokenResponse{}, errStatus
	}
	return decodeTokenResponse("Codex token exchange", response.Body, true)
}

func runXAIDeviceLogin(ctx context.Context, noBrowser bool, runtimeConfig oauthRuntime) (authData, error) {
	runtimeConfig = runtimeConfig.withDefaults()
	response, errRequest := runtimeConfig.client.Do(formRequest(http.MethodPost, xaiDeviceCodeURL, xaiDeviceCodeForm()))
	if errRequest != nil {
		return authData{}, fmt.Errorf("request xAI device authorization: %w", errRequest)
	}
	if errStatus := requireHTTPSuccess("xAI device authorization", response); errStatus != nil {
		return authData{}, errStatus
	}
	var device struct {
		DeviceCode              string        `json:"device_code"`
		UserCode                string        `json:"user_code"`
		VerificationURI         string        `json:"verification_uri"`
		VerificationURIComplete string        `json:"verification_uri_complete"`
		ExpiresIn               oauthInterval `json:"expires_in"`
		Interval                oauthInterval `json:"interval"`
	}
	if errDecode := json.Unmarshal(response.Body, &device); errDecode != nil {
		return authData{}, fmt.Errorf("decode xAI device authorization response: %w", errDecode)
	}
	device.DeviceCode = strings.TrimSpace(device.DeviceCode)
	device.UserCode = strings.TrimSpace(device.UserCode)
	if device.DeviceCode == "" || device.UserCode == "" || !device.ExpiresIn.Set || !device.ExpiresIn.Valid || device.ExpiresIn.Seconds <= 0 {
		return authData{}, fmt.Errorf("xAI device authorization response is missing required fields")
	}
	verificationURL, errURL := validateVerificationURL(firstNonEmpty(device.VerificationURIComplete, device.VerificationURI))
	if errURL != nil {
		return authData{}, errURL
	}

	runtimeConfig.notify(fmt.Sprintf("Open %s and enter code %s", verificationURL, device.UserCode))
	openLoginURL(noBrowser, verificationURL, runtimeConfig)
	pollInterval := -1.0
	if device.Interval.Set && device.Interval.Valid && device.Interval.Seconds > 0 {
		pollInterval = device.Interval.Seconds
	}
	token, errPoll := pollDeviceFlow(ctx, pollInterval, device.ExpiresIn.Seconds, true, runtimeConfig, func() devicePollResult {
		return pollXAIDevice(runtimeConfig.client, device.DeviceCode)
	})
	if errPoll != nil {
		return authData{}, fmt.Errorf("xAI device login: %w", errPoll)
	}
	return buildXAIAuthData(token, xaiTokenURL, runtimeConfig.now(), runtimeConfig.userAgent)
}

func pollXAIDevice(client oauthHTTPClient, deviceCode string) devicePollResult {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {xaiClientID},
		"device_code": {strings.TrimSpace(deviceCode)},
	}
	response, errRequest := client.Do(formRequest(http.MethodPost, xaiTokenURL, form))
	if errRequest != nil {
		return failedPoll(fmt.Errorf("poll xAI device authorization: %w", errRequest))
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		token, errToken := decodeTokenResponse("xAI token response", response.Body, false)
		if errToken != nil {
			return failedPoll(errToken)
		}
		return completedPoll(token)
	}
	return classifyPendingResponse("xAI device authorization", response)
}

type devicePollStatus int

const (
	devicePollPending devicePollStatus = iota
	devicePollSlowDown
	devicePollComplete
	devicePollFailed
)

type devicePollResult struct {
	status          devicePollStatus
	token           oauthTokenResponse
	err             error
	intervalSeconds float64
}

func completedPoll(token oauthTokenResponse) devicePollResult {
	return devicePollResult{status: devicePollComplete, token: token}
}

func failedPoll(err error) devicePollResult {
	return devicePollResult{status: devicePollFailed, err: err}
}

func classifyPendingResponse(action string, response oauthHTTPResponse) devicePollResult {
	errorCode, errorDescription, responseInterval := decodeOAuthError(response.Body)
	switch strings.ToLower(strings.TrimSpace(errorCode)) {
	case "authorization_pending", "deviceauth_authorization_pending", "pending", "not_found":
		return devicePollResult{status: devicePollPending}
	case "slow_down", "slowdown":
		return devicePollResult{status: devicePollSlowDown, intervalSeconds: validOAuthInterval(responseInterval)}
	case "access_denied", "authorization_denied", "expired_token", "authorization_declined", "bad_verification_code":
		return failedPoll(fmt.Errorf("%s failed: %s", action, safeOAuthError(errorCode, errorDescription)))
	}
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
		return devicePollResult{status: devicePollPending}
	}
	if response.StatusCode == http.StatusTooManyRequests {
		interval := validOAuthInterval(responseInterval)
		if interval <= 0 {
			if retryAfter, errParse := strconv.ParseFloat(strings.TrimSpace(response.Header.Get("Retry-After")), 64); errParse == nil && isFinite(retryAfter) {
				interval = retryAfter
			}
		}
		return devicePollResult{status: devicePollSlowDown, intervalSeconds: interval}
	}
	return failedPoll(httpStatusError(action, response, errorCode, errorDescription))
}

func pollDeviceFlow(ctx context.Context, intervalSeconds, expiresInSeconds float64, waitBeforeFirst bool, runtimeConfig oauthRuntime, poll func() devicePollResult) (oauthTokenResponse, error) {
	interval := normalizedPollInterval(intervalSeconds)
	lifetime := defaultFlowLifetime
	if expiresInSeconds > 0 && isFinite(expiresInSeconds) {
		lifetime = durationFromSeconds(expiresInSeconds)
	}
	deadline := runtimeConfig.now().Add(lifetime)
	if waitBeforeFirst {
		if errSleep := sleepUntilDeadline(ctx, interval, deadline, runtimeConfig); errSleep != nil {
			return oauthTokenResponse{}, errSleep
		}
	}
	for runtimeConfig.now().Before(deadline) {
		if errContext := ctx.Err(); errContext != nil {
			return oauthTokenResponse{}, errContext
		}
		result := poll()
		switch result.status {
		case devicePollComplete:
			return result.token, nil
		case devicePollFailed:
			if result.err == nil {
				return oauthTokenResponse{}, fmt.Errorf("OAuth device polling failed")
			}
			return oauthTokenResponse{}, result.err
		case devicePollSlowDown:
			if result.intervalSeconds > 0 {
				interval = normalizedPollInterval(result.intervalSeconds)
			} else {
				interval += slowDownIncrement
			}
		case devicePollPending:
		}
		if errSleep := sleepUntilDeadline(ctx, interval, deadline, runtimeConfig); errSleep != nil {
			return oauthTokenResponse{}, errSleep
		}
	}
	return oauthTokenResponse{}, fmt.Errorf("OAuth device flow timed out")
}

func normalizedPollInterval(seconds float64) time.Duration {
	if seconds < 0 || !isFinite(seconds) {
		return defaultPollInterval
	}
	interval := durationFromSeconds(seconds)
	if interval < minimumPollInterval {
		return minimumPollInterval
	}
	return interval
}

func sleepUntilDeadline(ctx context.Context, duration time.Duration, deadline time.Time, runtimeConfig oauthRuntime) error {
	remaining := deadline.Sub(runtimeConfig.now())
	if remaining <= 0 {
		return fmt.Errorf("OAuth device flow timed out")
	}
	if duration > remaining {
		duration = remaining
	}
	return runtimeConfig.sleep(ctx, duration)
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func generatePKCE(random io.Reader) (verifier, challenge string, err error) {
	verifier, err = randomURLSafe(random, 32)
	if err != nil {
		return "", "", fmt.Errorf("generate Codex PKCE verifier: %w", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func randomURLSafe(random io.Reader, size int) (string, error) {
	buffer := make([]byte, size)
	if _, errRead := io.ReadFull(random, buffer); errRead != nil {
		return "", errRead
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func jsonRequest(method, rawURL string, body []byte) oauthHTTPRequest {
	return oauthHTTPRequest{
		Method: method,
		URL:    rawURL,
		Header: http.Header{
			"Accept":       {"application/json"},
			"Content-Type": {"application/json"},
		},
		Body: body,
	}
}

func formRequest(method, rawURL string, form url.Values) oauthHTTPRequest {
	return oauthHTTPRequest{
		Method: method,
		URL:    rawURL,
		Header: http.Header{
			"Accept":       {"application/json"},
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
		Body: []byte(form.Encode()),
	}
}

func requireHTTPSuccess(action string, response oauthHTTPResponse) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	errorCode, errorDescription, _ := decodeOAuthError(response.Body)
	return httpStatusError(action, response, errorCode, errorDescription)
}

func decodeTokenResponse(action string, body []byte, requireExpiry bool) (oauthTokenResponse, error) {
	var payload struct {
		AccessToken  string        `json:"access_token"`
		RefreshToken string        `json:"refresh_token"`
		IDToken      string        `json:"id_token"`
		TokenType    string        `json:"token_type"`
		ExpiresIn    oauthInterval `json:"expires_in"`
	}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return oauthTokenResponse{}, fmt.Errorf("decode %s: %w", action, errDecode)
	}
	token := trimTokenResponse(oauthTokenResponse{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		IDToken:      payload.IDToken,
		TokenType:    payload.TokenType,
	})
	if token.AccessToken == "" || token.RefreshToken == "" {
		return oauthTokenResponse{}, fmt.Errorf("%s is missing required token fields", action)
	}
	if !payload.ExpiresIn.Set {
		if requireExpiry {
			return oauthTokenResponse{}, fmt.Errorf("%s is missing expires_in", action)
		}
		token.ExpiresIn = 3600
		return token, nil
	}
	if !payload.ExpiresIn.Valid || payload.ExpiresIn.Seconds <= 0 || payload.ExpiresIn.Seconds > float64(int(^uint(0)>>1)) {
		return oauthTokenResponse{}, fmt.Errorf("%s has invalid expires_in", action)
	}
	token.ExpiresIn = int(math.Ceil(payload.ExpiresIn.Seconds))
	return token, nil
}

func httpStatusError(action string, response oauthHTTPResponse, code, description string) error {
	detail := safeOAuthError(code, description)
	if detail == "" {
		detail = http.StatusText(response.StatusCode)
	}
	if detail == "" {
		detail = "request failed"
	}
	return fmt.Errorf("%s failed with HTTP %d: %s", action, response.StatusCode, detail)
}

func safeOAuthError(code, description string) string {
	code = strings.TrimSpace(code)
	description = strings.TrimSpace(description)
	value := code
	if description != "" && !strings.EqualFold(description, code) {
		if value != "" {
			value += ": "
		}
		value += description
	}
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}

func openLoginURL(noBrowser bool, rawURL string, runtimeConfig oauthRuntime) {
	if noBrowser {
		return
	}
	if errOpen := runtimeConfig.openURL(rawURL); errOpen != nil {
		runtimeConfig.notify("Could not open a browser automatically; open the URL above manually.")
	}
}
