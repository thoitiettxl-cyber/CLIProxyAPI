package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	piIdentity = "pi"

	codexAuthorizeURL      = "https://auth.openai.com/oauth/authorize"
	codexTokenURL          = "https://auth.openai.com/oauth/token"
	codexClientID          = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexRedirectURI       = "http://localhost:1455/auth/callback"
	codexDeviceUserCodeURL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	codexDeviceTokenURL    = "https://auth.openai.com/api/accounts/deviceauth/token"
	codexDeviceVerifyURL   = "https://auth.openai.com/codex/device"
	codexDeviceRedirectURI = "https://auth.openai.com/deviceauth/callback"
	codexScope             = "openid profile email offline_access"

	xaiClientID      = "b1a00492-073a-47ea-816f-4c329264a828"
	xaiScope         = "openid profile email offline_access grok-cli:access api:access"
	xaiDeviceCodeURL = "https://auth.x.ai/oauth2/device/code"
	xaiTokenURL      = "https://auth.x.ai/oauth2/token"
	xaiAPIBaseURL    = "https://api.x.ai/v1"

	codexPreserveClientIdentityKey = "codex_preserve_client_identity"
	openAIAuthClaimKey             = "https://api.openai.com/auth"
)

type authData struct {
	Provider    string
	ID          string
	FileName    string
	Label       string
	Prefix      string
	ProxyURL    string
	Disabled    bool
	StorageJSON []byte
	Metadata    map[string]any
	Attributes  map[string]string
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func buildCodexAuthorizationURL(state, challenge string) (string, error) {
	return buildCodexAuthorizationURLWithRedirect(state, challenge, codexRedirectURI)
}

func buildCodexAuthorizationURLWithRedirect(state, challenge, redirectURI string) (string, error) {
	state = strings.TrimSpace(state)
	challenge = strings.TrimSpace(challenge)
	redirectURI = strings.TrimSpace(redirectURI)
	if state == "" {
		return "", fmt.Errorf("Codex OAuth state is required")
	}
	if challenge == "" {
		return "", fmt.Errorf("Codex PKCE challenge is required")
	}
	if redirectURI == "" {
		return "", fmt.Errorf("Codex redirect URI is required")
	}
	params := url.Values{
		"response_type":              {"code"},
		"client_id":                  {codexClientID},
		"redirect_uri":               {redirectURI},
		"scope":                      {codexScope},
		"code_challenge":             {challenge},
		"code_challenge_method":      {"S256"},
		"state":                      {state},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
		"originator":                 {piIdentity},
	}
	return codexAuthorizeURL + "?" + params.Encode(), nil
}

func xaiDeviceCodeForm() url.Values {
	return url.Values{
		"client_id": {xaiClientID},
		"scope":     {xaiScope},
		"referrer":  {piIdentity},
	}
}

func normalizeLoginMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "codex", "codex-device", "xai":
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported Pi login mode %q; use codex, codex-device, or xai", raw)
	}
}

func validateVerificationURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, errParse := url.Parse(raw)
	if errParse != nil || parsed.Scheme != "https" || strings.TrimSpace(parsed.Host) == "" || parsed.User != nil {
		return "", fmt.Errorf("untrusted OAuth verification URL")
	}
	return parsed.String(), nil
}

func buildCodexAuthData(token oauthTokenResponse, now time.Time, userAgent string) (authData, error) {
	token = trimTokenResponse(token)
	if token.AccessToken == "" || token.RefreshToken == "" || token.ExpiresIn <= 0 {
		return authData{}, fmt.Errorf("Codex token response is missing required fields")
	}

	accessClaims := parseJWTClaims(token.AccessToken)
	idClaims := parseJWTClaims(token.IDToken)
	accountID := firstNonEmpty(openAIAuthClaim(accessClaims, "chatgpt_account_id"), openAIAuthClaim(idClaims, "chatgpt_account_id"))
	if accountID == "" {
		return authData{}, fmt.Errorf("Codex access token is missing account identity")
	}
	email := firstNonEmpty(claimString(accessClaims, "email"), claimString(idClaims, "email"))
	planType := firstNonEmpty(openAIAuthClaim(accessClaims, "chatgpt_plan_type"), openAIAuthClaim(idClaims, "chatgpt_plan_type"))

	now = now.UTC()
	metadata := commonPiMetadata(userAgent)
	metadata["type"] = "codex"
	metadata["access_token"] = token.AccessToken
	metadata["refresh_token"] = token.RefreshToken
	if token.IDToken != "" {
		metadata["id_token"] = token.IDToken
	}
	if token.TokenType != "" {
		metadata["token_type"] = token.TokenType
	}
	metadata["account_id"] = accountID
	if email != "" {
		metadata["email"] = email
	}
	metadata["expired"] = now.Add(time.Duration(token.ExpiresIn) * time.Second).Format(time.RFC3339)
	metadata["last_refresh"] = now.Format(time.RFC3339)
	metadata[codexPreserveClientIdentityKey] = true

	attributes := commonPiAttributes(userAgent)
	if planType != "" {
		attributes["plan_type"] = planType
	}
	fileName := codexCredentialFileName(email, planType, accountID)
	return authData{
		Provider:   "codex",
		ID:         fileName,
		FileName:   fileName,
		Label:      firstNonEmpty(email, accountID),
		Metadata:   metadata,
		Attributes: attributes,
	}, nil
}

func buildXAIAuthData(token oauthTokenResponse, tokenEndpoint string, now time.Time, userAgent string) (authData, error) {
	token = trimTokenResponse(token)
	if token.AccessToken == "" || token.RefreshToken == "" {
		return authData{}, fmt.Errorf("xAI token response is missing required fields")
	}
	if token.ExpiresIn <= 0 {
		token.ExpiresIn = 3600
	}

	idClaims := parseJWTClaims(token.IDToken)
	accessClaims := parseJWTClaims(token.AccessToken)
	email := firstNonEmpty(claimString(idClaims, "email"), claimString(accessClaims, "email"))
	subject := firstNonEmpty(claimString(idClaims, "sub"), claimString(accessClaims, "sub"))
	now = now.UTC()
	metadata := commonPiMetadata(userAgent)
	metadata["type"] = "xai"
	metadata["auth_kind"] = "oauth"
	metadata["access_token"] = token.AccessToken
	metadata["refresh_token"] = token.RefreshToken
	if token.IDToken != "" {
		metadata["id_token"] = token.IDToken
	}
	if token.TokenType != "" {
		metadata["token_type"] = token.TokenType
	}
	metadata["expires_in"] = token.ExpiresIn
	metadata["expired"] = now.Add(time.Duration(token.ExpiresIn) * time.Second).Format(time.RFC3339)
	metadata["last_refresh"] = now.Format(time.RFC3339)
	metadata["base_url"] = xaiAPIBaseURL
	metadata["token_endpoint"] = strings.TrimSpace(tokenEndpoint)
	if email != "" {
		metadata["email"] = email
	}
	if subject != "" {
		metadata["sub"] = subject
	}

	attributes := commonPiAttributes(userAgent)
	attributes["auth_kind"] = "oauth"
	attributes["base_url"] = xaiAPIBaseURL
	fileName := xaiCredentialFileName(email, subject, now)
	return authData{
		Provider:   "xai",
		ID:         fileName,
		FileName:   fileName,
		Label:      firstNonEmpty(email, subject),
		Metadata:   metadata,
		Attributes: attributes,
	}, nil
}

func commonPiMetadata(userAgent string) map[string]any {
	return map[string]any{
		"login_identity": piIdentity,
		"headers": map[string]any{
			"Originator": piIdentity,
			"User-Agent": strings.TrimSpace(userAgent),
		},
	}
}

func commonPiAttributes(userAgent string) map[string]string {
	return map[string]string{
		"header:Originator": piIdentity,
		"header:User-Agent": strings.TrimSpace(userAgent),
	}
}

func trimTokenResponse(token oauthTokenResponse) oauthTokenResponse {
	token.AccessToken = strings.TrimSpace(token.AccessToken)
	token.RefreshToken = strings.TrimSpace(token.RefreshToken)
	token.IDToken = strings.TrimSpace(token.IDToken)
	token.TokenType = strings.TrimSpace(token.TokenType)
	return token
}

func parseJWTClaims(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil
	}
	payload, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return nil
	}
	claims := make(map[string]any)
	if errUnmarshal := json.Unmarshal(payload, &claims); errUnmarshal != nil {
		return nil
	}
	return claims
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func openAIAuthClaim(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	nested, _ := claims[openAIAuthClaimKey].(map[string]any)
	return claimString(nested, key)
}

func codexCredentialFileName(email, planType, accountID string) string {
	identity := sanitizeFileSegment(email)
	if identity == "" {
		identity = "account"
	}
	parts := []string{"codex", "pi", identity}
	if plan := sanitizeFileSegment(planType); plan != "" {
		parts = append(parts, plan)
	}
	parts = append(parts, shortHash(accountID))
	return strings.Join(parts, "-") + ".json"
}

func xaiCredentialFileName(email, subject string, now time.Time) string {
	identity := sanitizeFileSegment(firstNonEmpty(email, subject))
	if identity == "" {
		identity = fmt.Sprintf("%d", now.UnixMilli())
	}
	return "xai-pi-" + identity + "-" + shortHash(firstNonEmpty(subject, email, identity)) + ".json"
}

func sanitizeFileSegment(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '@' || char == '.' || char == '_' || char == '-':
			builder.WriteRune(char)
		default:
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(digest[:])[:8]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func formatPiUserAgent(platform, release, arch string) string {
	platform = strings.TrimSpace(platform)
	release = strings.TrimSpace(release)
	arch = strings.TrimSpace(arch)
	if platform == "windows" {
		platform = "win32"
	}
	switch arch {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "ia32"
	}
	return fmt.Sprintf("pi (%s %s; %s)", platform, release, arch)
}

func currentPiUserAgent() string {
	return formatPiUserAgent(runtime.GOOS, currentOSRelease(), runtime.GOARCH)
}

func currentOSRelease() string {
	if raw, errRead := os.ReadFile("/proc/sys/kernel/osrelease"); errRead == nil {
		if release := strings.TrimSpace(string(raw)); release != "" {
			return release
		}
	}
	output, errRun := exec.Command("uname", "-r").Output()
	if errRun == nil {
		if release := strings.TrimSpace(string(output)); release != "" {
			return release
		}
	}
	return runtime.GOOS
}
