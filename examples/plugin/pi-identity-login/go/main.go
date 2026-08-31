package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	piLoginFlag              = "pi-login"
	maxPluginRequestBytes    = 8 << 20
	maxHostResponseBytes     = 4 << 20
	defaultCodexCallbackPort = 1455
)

type rpcEnvelope struct {
	OK     bool              `json:"ok"`
	Result json.RawMessage   `json:"result,omitempty"`
	Error  *rpcEnvelopeError `json:"error,omitempty"`
}

type rpcEnvelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type pluginRegistration struct {
	SchemaVersion uint32                       `json:"schema_version"`
	Metadata      pluginapi.Metadata           `json:"metadata"`
	Capabilities  pluginRegistrationCapability `json:"capabilities"`
}

type pluginRegistrationCapability struct {
	CommandLinePlugin bool `json:"command_line_plugin"`
}

type commandLineExecutionResponse struct {
	Stdout   []byte
	Stderr   []byte
	Auths    []authData
	ExitCode int
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil || uint32(host.abi_version) != pluginabi.ABIVersion {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writePluginResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	if uint64(requestLen) > maxPluginRequestBytes {
		writePluginResponse(response, errorEnvelope("request_too_large", "plugin request is too large"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handlePluginMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writePluginResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writePluginResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	C.store_host_api(nil)
}

func handlePluginMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(pluginDescriptor())
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		return okEnvelope(map[string]any{})
	case pluginabi.MethodCommandLineRegister:
		return okEnvelope(pluginapi.CommandLineRegistrationResponse{Flags: []pluginapi.CommandLineFlag{{
			Name:         piLoginFlag,
			Usage:        "Authenticate with Pi identity: codex, codex-device, or xai",
			Type:         "string",
			DefaultValue: "",
		}}})
	case pluginabi.MethodCommandLineExecute:
		return executePiLoginCommand(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func pluginDescriptor() pluginRegistration {
	return pluginRegistration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "pi-identity-login",
			Version:          "0.1.0",
			Author:           "router-for-me",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
		},
		Capabilities: pluginRegistrationCapability{CommandLinePlugin: true},
	}
}

func executePiLoginCommand(rawRequest []byte) ([]byte, error) {
	var request pluginapi.CommandLineExecutionRequest
	if errDecode := json.Unmarshal(rawRequest, &request); errDecode != nil {
		return okEnvelope(commandFailure(fmt.Errorf("decode command-line request: %w", errDecode)))
	}
	trigger, okTrigger := request.TriggeredFlags[piLoginFlag]
	if !okTrigger || !trigger.Set {
		return okEnvelope(commandFailure(fmt.Errorf("--%s was not triggered", piLoginFlag)))
	}
	mode, errMode := normalizeLoginMode(trigger.Value)
	if errMode != nil {
		return okEnvelope(commandFailure(errMode))
	}
	noBrowser, errNoBrowser := commandLineBool(request.Flags, "no-browser")
	if errNoBrowser != nil {
		return okEnvelope(commandFailure(errNoBrowser))
	}
	callbackPort := defaultCodexCallbackPort
	if mode == "codex" {
		var errPort error
		callbackPort, errPort = commandLineCallbackPort(request.Flags)
		if errPort != nil {
			return okEnvelope(commandFailure(errPort))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultFlowLifetime)
	defer cancel()
	auth, errLogin := loginWithPi(ctx, mode, noBrowser, oauthRuntime{
		client:       hostOAuthHTTPClient{},
		callbackPort: callbackPort,
		notify:       notifyTerminal,
		openURL:      openBrowser,
		userAgent:    currentPiUserAgent(),
	})
	if errLogin != nil {
		return okEnvelope(commandFailure(errLogin))
	}
	return okEnvelope(commandLineExecutionResponse{
		Stdout: []byte(fmt.Sprintf("Pi identity OAuth succeeded for %s.\n", auth.Provider)),
		Auths:  []authData{auth},
	})
}

func commandFailure(err error) commandLineExecutionResponse {
	message := "Pi identity OAuth failed"
	if err != nil {
		message += ": " + err.Error()
	}
	return commandLineExecutionResponse{Stderr: []byte(message + "\n"), ExitCode: 1}
}

func commandLineBool(flags map[string]pluginapi.CommandLineFlagValue, name string) (bool, error) {
	value, exists := flags[name]
	if !exists || strings.TrimSpace(value.Value) == "" {
		return false, nil
	}
	parsed, errParse := strconv.ParseBool(value.Value)
	if errParse != nil {
		return false, fmt.Errorf("invalid -%s value %q", name, value.Value)
	}
	return parsed, nil
}

func commandLineCallbackPort(flags map[string]pluginapi.CommandLineFlagValue) (int, error) {
	value, exists := flags["oauth-callback-port"]
	if !exists || strings.TrimSpace(value.Value) == "" || strings.TrimSpace(value.Value) == "0" {
		return defaultCodexCallbackPort, nil
	}
	port, errParse := strconv.Atoi(strings.TrimSpace(value.Value))
	if errParse != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid -oauth-callback-port value %q", value.Value)
	}
	return port, nil
}

func notifyTerminal(message string) {
	message = strings.TrimSpace(message)
	if message != "" {
		_, _ = fmt.Fprintln(os.Stderr, message)
	}
}

func openBrowser(rawURL string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", rawURL)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		command = exec.Command("xdg-open", rawURL)
	}
	if errStart := command.Start(); errStart != nil {
		return errStart
	}
	if command.Process != nil {
		return command.Process.Release()
	}
	return nil
}

type hostOAuthHTTPClient struct{}

func (hostOAuthHTTPClient) Do(request oauthHTTPRequest) (oauthHTTPResponse, error) {
	hostRequest := pluginapi.HTTPRequest{
		Method:  request.Method,
		URL:     request.URL,
		Headers: request.Header.Clone(),
		Body:    append([]byte(nil), request.Body...),
	}
	var hostResponse pluginapi.HTTPResponse
	if errCall := callHost(pluginabi.MethodHostHTTPDo, hostRequest, &hostResponse); errCall != nil {
		return oauthHTTPResponse{}, errCall
	}
	return oauthHTTPResponse{
		StatusCode: hostResponse.StatusCode,
		Header:     hostResponse.Headers.Clone(),
		Body:       append([]byte(nil), hostResponse.Body...),
	}, nil
}

func callHost(method string, request any, result any) error {
	payload, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return fmt.Errorf("marshal host callback %s: %w", method, errMarshal)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var requestPointer *C.uint8_t
	if len(payload) > 0 {
		requestPointer = (*C.uint8_t)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(requestPointer))
	}
	var response C.cliproxy_buffer
	if status := C.call_host_api(cMethod, requestPointer, C.size_t(len(payload)), &response); status != 0 {
		return fmt.Errorf("host callback %s is unavailable", method)
	}
	if response.ptr != nil {
		defer C.free_host_buffer(response.ptr, response.len)
	}
	if uint64(response.len) > maxHostResponseBytes {
		return fmt.Errorf("host callback %s response is too large", method)
	}
	var raw []byte
	if response.ptr != nil && response.len > 0 {
		raw = C.GoBytes(response.ptr, C.int(response.len))
	}
	var envelope rpcEnvelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
		return fmt.Errorf("decode host callback %s: %w", method, errDecode)
	}
	if !envelope.OK {
		if envelope.Error != nil && strings.TrimSpace(envelope.Error.Message) != "" {
			return fmt.Errorf("host callback %s failed: %s", method, envelope.Error.Message)
		}
		return fmt.Errorf("host callback %s failed", method)
	}
	if result == nil || len(envelope.Result) == 0 {
		return nil
	}
	if errResult := json.Unmarshal(envelope.Result, result); errResult != nil {
		return fmt.Errorf("decode host callback %s result: %w", method, errResult)
	}
	return nil
}

func okEnvelope(result any) ([]byte, error) {
	rawResult, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(rpcEnvelope{OK: true, Result: rawResult})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(rpcEnvelope{
		OK: false,
		Error: &rpcEnvelopeError{
			Code:    code,
			Message: message,
		},
	})
	return raw
}

func writePluginResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	pointer := C.CBytes(raw)
	if pointer == nil {
		return
	}
	response.ptr = pointer
	response.len = C.size_t(len(raw))
}
