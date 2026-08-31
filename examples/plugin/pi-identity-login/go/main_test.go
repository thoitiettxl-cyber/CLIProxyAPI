package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestPluginDescriptorExposesOnlyCommandLineCapability(t *testing.T) {
	descriptor := pluginDescriptor()
	if descriptor.SchemaVersion != pluginabi.SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", descriptor.SchemaVersion, pluginabi.SchemaVersion)
	}
	if descriptor.Metadata.Name != "pi-identity-login" {
		t.Fatalf("plugin name = %q", descriptor.Metadata.Name)
	}
	if !descriptor.Capabilities.CommandLinePlugin {
		t.Fatal("CommandLinePlugin capability = false")
	}
}

func TestCommandLineRegistrationUsesSingleValidatedModeFlag(t *testing.T) {
	raw, err := handlePluginMethod(pluginabi.MethodCommandLineRegister, nil)
	if err != nil {
		t.Fatalf("handlePluginMethod() error = %v", err)
	}
	var envelope rpcEnvelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
		t.Fatalf("decode envelope: %v", errDecode)
	}
	var registration pluginapi.CommandLineRegistrationResponse
	if errDecode := json.Unmarshal(envelope.Result, &registration); errDecode != nil {
		t.Fatalf("decode registration: %v", errDecode)
	}
	if len(registration.Flags) != 1 {
		t.Fatalf("flag count = %d, want 1", len(registration.Flags))
	}
	flag := registration.Flags[0]
	if flag.Name != piLoginFlag || flag.Type != "string" {
		t.Fatalf("flag = %#v", flag)
	}
}

func TestExecutePiLoginCommandRejectsUnknownModeBeforeOAuth(t *testing.T) {
	request := pluginapi.CommandLineExecutionRequest{
		TriggeredFlags: map[string]pluginapi.CommandLineFlagValue{
			piLoginFlag: {Name: piLoginFlag, Type: "string", Value: "unknown", Set: true},
		},
	}
	rawRequest, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	raw, err := executePiLoginCommand(rawRequest)
	if err != nil {
		t.Fatalf("executePiLoginCommand() error = %v", err)
	}
	var envelope rpcEnvelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
		t.Fatalf("decode envelope: %v", errDecode)
	}
	var response commandLineExecutionResponse
	if errDecode := json.Unmarshal(envelope.Result, &response); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", response.ExitCode)
	}
	if len(response.Auths) != 0 {
		t.Fatalf("Auths = %d, want 0", len(response.Auths))
	}
}

func TestCommandLineCallbackPortUsesHostOverride(t *testing.T) {
	flags := map[string]pluginapi.CommandLineFlagValue{
		"oauth-callback-port": {Name: "oauth-callback-port", Value: "9876", Set: true},
	}
	port, err := commandLineCallbackPort(flags)
	if err != nil || port != 9876 {
		t.Fatalf("commandLineCallbackPort() = %d, %v", port, err)
	}
	redirectURI, err := codexCallbackRedirectURI(port)
	if err != nil || redirectURI != "http://localhost:9876/auth/callback" {
		t.Fatalf("codexCallbackRedirectURI() = %q, %v", redirectURI, err)
	}
}

func TestCommandLineAuthDataRoundTripsToHostSchema(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	access := testJWT(t, map[string]any{
		"email": "person@example.com",
		openAIAuthClaimKey: map[string]any{
			"chatgpt_account_id": "acct-123",
			"chatgpt_plan_type":  "pro",
		},
	})
	auth, err := buildCodexAuthData(oauthTokenResponse{
		AccessToken:  access,
		RefreshToken: "refresh-secret",
		ExpiresIn:    3600,
	}, now, "pi (linux test; arm64)")
	if err != nil {
		t.Fatalf("buildCodexAuthData() error = %v", err)
	}
	raw, errMarshal := json.Marshal(commandLineExecutionResponse{Auths: []authData{auth}})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var host pluginapi.CommandLineExecutionResponse
	if errDecode := json.Unmarshal(raw, &host); errDecode != nil {
		t.Fatalf("host decode: %v", errDecode)
	}
	if len(host.Auths) != 1 {
		t.Fatalf("Auths = %d, want 1", len(host.Auths))
	}
	got := host.Auths[0]
	if got.Provider != "codex" || !strings.HasPrefix(got.FileName, "codex-pi-") {
		t.Fatalf("host auth = %#v", got)
	}
	if got.Metadata["login_identity"] != piIdentity {
		t.Fatalf("login_identity = %#v", got.Metadata["login_identity"])
	}
	if got.Metadata[codexPreserveClientIdentityKey] != true {
		t.Fatalf("%s = %#v", codexPreserveClientIdentityKey, got.Metadata[codexPreserveClientIdentityKey])
	}
}
