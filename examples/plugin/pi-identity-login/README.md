# Pi Identity Login Plugin

`pi-identity-login` is an opt-in CLI-only plugin for acquiring standalone Codex or xAI OAuth credentials with Pi identity parameters. It returns native `codex` or `xai` auth records, so CLIProxyAPI continues to own persistence, refresh, routing, and execution.

The plugin does not read or import `~/.pi/agent/auth.json`, and it does not change the native `--codex-login`, `--codex-device-login`, or `--xai-login` commands.

## Build and test

From the repository root:

```bash
go -C examples/plugin/pi-identity-login/go test ./...
make -C examples/plugin bin/pi-identity-login.so
```

On macOS, replace `.so` with `.dylib`. The general `make -C examples/plugin build` target also builds this plugin alongside the other examples.

## Enable

Place the shared library in the configured plugin directory under the exact base name `pi-identity-login` and enable both the plugin host and this plugin ID:

```yaml
plugins:
  enabled: true
  dir: "examples/plugin/bin"
  configs:
    pi-identity-login:
      enabled: true
      priority: 100
```

Restart CLIProxyAPI after installing or removing an in-process plugin.

Go `c-shared` plugins cannot currently be `dlopen`'d on musl/Alpine hosts (`initial-exec TLS resolves to dynamic definition`). Build and offline tests still work there; load the plugin on a glibc host, or start the process with the library preloaded. This is a Go+musl limitation, not Pi-specific behavior.

The Magisk/Android CLIProxyAPI core is linux/arm64 glibc. Build that `.so` with GitHub Actions workflow `build-pi-identity-login-plugin`, or cross-compile from a glibc environment:

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
  go -C examples/plugin/pi-identity-login/go build -buildmode=c-shared \
  -o pi-identity-login.so .
```

`readelf -d pi-identity-login.so` must show `NEEDED libc.so.6`, not `libc.musl-aarch64.so.1`. Install the artifact as `plugins/linux/arm64/pi-identity-login.so`.

## Login modes

```bash
# Codex browser/PKCE flow
cli-proxy-api --config config.yaml --pi-login=codex

# Codex device flow (headless recovery path)
cli-proxy-api --config config.yaml --pi-login=codex-device --no-browser

# xAI device flow
cli-proxy-api --config config.yaml --pi-login=xai --no-browser
```

The Codex browser flow defaults to callback port `1455` and honors the host's `--oauth-callback-port` override. All OAuth HTTP calls use `host.http.do`, which retains the host's configured proxy transport. The host persists successful credentials in its resolved auth directory.

## Identity and routing behavior

The plugin stores:

- `login_identity: pi`;
- `Originator: pi` and a Pi-shaped `User-Agent` in credential-owned custom headers;
- `codex_preserve_client_identity: true` for Codex credentials only.

The Codex marker disables cloaking and optional identity-confusion transforms only for that credential. Unmarked and explicitly false credentials retain the existing Codex behavior, including the global `disable-codex-cloaking` setting. xAI credentials do not set `using_api`, so built-in xAI OAuth routing remains unchanged.

Generated files use `codex-pi-*.json` or `xai-pi-*.json` names to avoid merging with native-login files. Removing the plugin unregisters only `--pi-login`; native login flags and behavior remain available. Existing credentials remain ordinary native-provider auth files and can be removed through the normal auth-file workflow.

## Security notes

- Dynamic plugins are trusted in-process code; install only binaries you built or otherwise trust.
- Authorization URLs and device codes are displayed locally, but access and refresh tokens are never printed.
- OAuth error handling does not echo arbitrary response bodies.
- The callback listener binds only to IPv4 loopback and is closed after success, error, or timeout.
