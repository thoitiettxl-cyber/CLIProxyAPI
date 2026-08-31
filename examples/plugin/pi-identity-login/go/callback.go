package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type codexCallbackResult struct {
	code string
	err  error
}

type localCodexCallback struct {
	server  *http.Server
	results chan codexCallbackResult
	errors  chan error
	once    sync.Once
}

func startLocalCodexCallback(expectedState string, port int) (codexCallbackWaiter, error) {
	expectedState = strings.TrimSpace(expectedState)
	if expectedState == "" {
		return nil, fmt.Errorf("OAuth state is required")
	}
	if _, errRedirect := codexCallbackRedirectURI(port); errRedirect != nil {
		return nil, errRedirect
	}
	listener, errListen := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if errListen != nil {
		return nil, errListen
	}
	callback := &localCodexCallback{
		results: make(chan codexCallbackResult, 1),
		errors:  make(chan error, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", callback.handler(expectedState))
	callback.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() {
		if errServe := callback.server.Serve(listener); errServe != nil && !errors.Is(errServe, http.ErrServerClosed) {
			callback.errors <- errServe
		}
	}()
	return callback, nil
}

func codexCallbackRedirectURI(port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("Codex OAuth callback port must be between 1 and 65535")
	}
	callbackURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("localhost", strconv.Itoa(port)),
		Path:   "/auth/callback",
	}
	return callbackURL.String(), nil
}

func (callback *localCodexCallback) handler(expectedState string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query := request.URL.Query()
		if query.Get("state") != expectedState {
			http.Error(writer, "OAuth state mismatch", http.StatusBadRequest)
			return
		}
		if oauthError := strings.TrimSpace(query.Get("error")); oauthError != "" {
			description := safeOAuthError(oauthError, query.Get("error_description"))
			callback.deliver(codexCallbackResult{err: fmt.Errorf("Codex authorization failed: %s", description)})
			http.Error(writer, "Authorization failed. Return to the terminal for details.", http.StatusBadRequest)
			return
		}
		code := strings.TrimSpace(query.Get("code"))
		if code == "" {
			http.Error(writer, "Authorization code is missing", http.StatusBadRequest)
			return
		}
		callback.deliver(codexCallbackResult{code: code})
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<!doctype html><html><body><h1>Authentication complete</h1><p>You can close this window and return to CLIProxyAPI.</p></body></html>"))
	}
}

func (callback *localCodexCallback) deliver(result codexCallbackResult) {
	callback.once.Do(func() {
		callback.results <- result
	})
}

func (callback *localCodexCallback) Wait(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("Codex authorization callback: %w", ctx.Err())
	case errServe := <-callback.errors:
		return "", fmt.Errorf("Codex authorization callback server: %w", errServe)
	case result := <-callback.results:
		return result.code, result.err
	}
}

func (callback *localCodexCallback) Close() error {
	if callback == nil || callback.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if errShutdown := callback.server.Shutdown(ctx); errShutdown != nil && !errors.Is(errShutdown, http.ErrServerClosed) {
		return errShutdown
	}
	return nil
}
