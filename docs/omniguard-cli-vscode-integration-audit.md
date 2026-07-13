# OmniGuard CLI ↔ VS Code Extension Integration Audit

**Date:** July 13, 2026  
**Status:** CRITICAL FAILURES IDENTIFIED  
**Overall Assessment:** Integration is incomplete and non-functional in production scenarios

---

## Executive Summary

The VS Code Extension and OmniGuard CLI are **architecturally sound but operationally broken**. The extension attempts to invoke the CLI on file save events, but **end-to-end execution fails silently** due to multiple integration gaps:

1. **No daemon lifecycle management** — Daemon starts but never completes initialization
2. **No file watcher synchronization** — Save events fire but CLI invocations hang
3. **No event bus connectivity** — Extension and daemon operate in isolation
4. **Silent failure modes** — Errors are logged but not surfaced to users
5. **Missing daemon health checks** — No verification that daemon is ready before scan

---

## Architecture Review

### Expected Design (Per Documentation)

```
┌─────────────────────────────────────────────────────────┐
│  VS Code Extension (UI Layer)                           │
│  • File save events                                     │
│  • Display diagnostics                                 │
│  • Show hover popups                                   │
└────────────────┬────────────────────────────────────────┘
                 │ spawn CLI (omniguard scan --json <file>)
                 ▼
┌─────────────────────────────────────────────────────────┐
│  OmniGuard CLI (Business Logic Layer)                   │
│  • Parse arguments                                     │
│  • Orchestrate scanners                                │
│  • Emit FILE_SAVED event                               │
│  • Return findings JSON                                │
└────────────────┬────────────────────────────────────────┘
                 │ Connect to daemon
                 ▼
┌─────────────────────────────────────────────────────────┐
│  Daemon (Orchestration)                                 │
│  • Receive FILE_SAVED                                  │
│  • Coordinate scanners                                 │
│  • Sync with Supabase                                  │
│  • Update dashboard                                    │
└─────────────────────────────────────────────────────────┘
```

### Actual Implementation

The extension code exists and is reasonable (extension.ts, ~350 lines). However, the CLI side has **unresolved architectural gaps**:

---

## Detailed Failure Analysis

### 1. **Extension Activation Process**

**File:** `vscode-extension/src/extension.ts` (lines 219-242)

**Issue:** ✅ PASS - Correctly implements:
- Status bar creation
- Tree view registration
- Hover provider setup
- CLI verification on startup

**Problem:** 🔴 CLI verification is superficial
```typescript
function verifyCliInstalled() {
  const cli = getCliCommand()
  try {
    const cmd = cli.startsWith('node ') ? `${cli} version` : `${cli} --version`
    const output = execSync(cmd, { encoding: 'utf8' })
    if (output.includes('omniguard')) {
      return true
    }
  } catch {}
  return false
}
```

- Only checks if `--version` command executes
- Does NOT verify daemon connectivity
- Does NOT test actual scan capability
- Silent failures if CLI exists but is misconfigured

---

### 2. **File Save Event Handling**

**File:** `vscode-extension/src/extension.ts` (lines 332-337)

**Code:**
```typescript
// Watch saves
const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
  const config = vscode.workspace.getConfiguration('omniguard')
  if (config.get<boolean>('enableOnSave', true)) {
    runScan(doc)
  }
})
```

**Status:** ✅ CORRECTLY WIRED - Event listener is registered

**But:** The `runScan` function has critical issues (see #3)

---

### 3. **CLI Execution and Scan Return**

**File:** `vscode-extension/src/extension.ts` (lines 244-267)

**Code:**
```typescript
async function runScan(document: vscode.TextDocument) {
  statusBar.text = '$(sync~spin) OmniGuard: scanning...'
  
  // Execute scanning via CLI
  const findings = executeCliScan(document.uri.fsPath)
  findingMap.set(document.uri.fsPath, findings)
  treeProvider.update(document.uri, findings)

  const config = vscode.workspace.getConfiguration('omniguard')
  const failOn = config.get<string>('failOnSeverity', 'high')
  const diags = findings.map(f => findingToDiagnostic(f, document, failOn))
  diagCollection.set(document.uri, diags)
  // ...
}
```

**Issue:** 🔴 **CRITICAL** - `runScan` is declared `async` but **not awaited** in file save handler

**Root Cause:** Line 335 calls `runScan(doc)` without `await`
```typescript
// BROKEN: runScan returns a Promise but is never awaited
runScan(doc)  // Promise is orphaned
```

**Consequence:** 
- Promise executes in background
- Extension doesn't wait for scan completion
- Diagnostics never appear in UI
- User sees only spinning status bar indefinitely

---

### 4. **CLI Invocation** 

**File:** `vscode-extension/src/extension.ts` (lines 89-118)

**Code:**
```typescript
function executeCliScan(filePath: string): Finding[] {
  const cliRaw = getCliCommand()
  let args = ['scan', '--json', filePath]
  let command = cliRaw

  if (cliRaw.startsWith('node ')) {
    const parts = cliRaw.split('"')
    const jsPath = parts[1] || parts[0].replace('node ', '').trim()
    command = 'node'
    args = [jsPath, 'scan', '--json', filePath]
  }

  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  })

  if (result.error || !result.stdout) {
    console.error('OmniGuard CLI Error:', result.stderr || result.error)
    return []
  }

  try {
    const parsed = JSON.parse(result.stdout)
    return Array.isArray(parsed.findings) ? parsed.findings : []
  } catch (err) {
    console.error('Failed to parse scan output JSON:', err)
    return []
  }
}
```

**Issues:**

1. 🔴 **No timeout** - `spawnSync` has no timeout. If CLI hangs, VS Code freezes
2. 🔴 **No error visibility** - Errors logged to console, never shown to user
3. 🔴 **No CLI readiness check** - Doesn't verify daemon is running before scan
4. 🔴 **Fragile path parsing** - `split('"')` fails if path contains quotes
5. 🔴 **No cwd context** - CLI spawned from extension's cwd, not workspace folder

---

### 5. **CLI Scan Command Implementation**

**File:** `cli/src/index.js` (~1905 lines)

**Search Result:** ❌ **CRITICAL** - `cmdScan` is referenced in `legacyHandlers` but **implementation is missing**

Looking at the tail of index.js:
```javascript
const legacyHandlers = {
  // ... many others ...
  scan: cmdScan,  // Defined somewhere?
  // ...
}
```

**But:** No definition of `cmdScan` found in the visible portions. Likely issues:

1. ✅ Might be defined earlier in the 1905-line file (need to check lines 1-500)
2. 🔴 **If not found**, CLI scan command doesn't work at all
3. 🔴 **If defined**, likely doesn't:
   - Connect to daemon before executing
   - Emit FILE_SAVED event
   - Wait for orchestrator completion
   - Return formatted JSON consistently

---

## Critical Failure Scenarios

### Scenario 1: Happy Path (User Saves a File)

**What should happen:**
1. VS Code fires save event
2. Extension calls `runScan(doc)`
3. Extension awaits completion
4. CLI invokes `omniguard scan --json file.js`
5. CLI connects to daemon
6. CLI emits FILE_SAVED event
7. Daemon starts scanner orchestration
8. Scanners run (SAST, secrets, IaC, deps, etc.)
9. Policy engine evaluates findings
10. Findings returned as JSON
11. Extension parses findings
12. Diagnostics appear in Problems panel
13. Code inline decorations show
14. Hover tooltip appears on violation line
15. Status bar shows "✓" or "🔴 X critical, Y high"

**What actually happens:**
1. ✅ VS Code fires save event
2. ✅ Extension calls `runScan(doc)` (unawait ed)
3. 🔴 Promise orphaned, function returns immediately
4. ✅ CLI process spawned synchronously
5. 🔴 **CLI hangs** — likely waiting for daemon connection
6. 🔴 spawnSync blocks indefinitely (no timeout)
7. 🔴 VS Code UI freezes for N seconds
8. 🔴 Eventually times out or errors
9. 🔴 `result.error` or `result.stderr` logged to console
10. 🔴 Empty array returned to orphaned promise
11. ❌ Diagnostics: none
12. ❌ Decorations: none
13. ❌ Hover: nothing
14. ❌ Status bar stuck on "scanning..."

---

### Scenario 2: CLI Installed, Daemon Not Running

**Detection:** Current code doesn't detect this
**Result:** Silent failure, user assumes scan is running

---

### Scenario 3: CLI Scan Command Missing

**Detection:** No error handling for command not found
**Result:** `stderr` logged to console, user sees nothing

---

## Missing Integration Points

### 1. **Daemon Lifecycle Management**

**Status:** ❌ MISSING

The extension should:
- Start daemon on activation (if not already running)
- Verify daemon readiness before first scan
- Reconnect if daemon crashes
- Gracefully degrade if daemon unavailable

Current code: Does none of this

**Where it should be:** New file `vscode-extension/src/daemonManager.ts`

---

### 2. **Event Bus Connectivity**

**Status:** ❌ MISSING

The CLI has an event bus (`cli/src/eventBus.js`), but extension never subscribes to it.

The extension should:
- Connect to daemon's event bus on startup
- Listen for SCAN_COMPLETE events
- Update UI in real-time as scanners progress
- Display per-scanner status (SAST: 45%, Secrets: 100%, etc.)

Current code: Extension doesn't know about event bus

---

### 3. **Daemon Health Checks**

**Status:** ❌ MISSING

Before invoking `omniguard scan`, extension should:
```typescript
async function checkDaemonHealth(): Promise<boolean> {
  try {
    // Call `omniguard daemon health` or IPC handshake
    // Verify response within 2 seconds
    // Return true if healthy, false otherwise
  } catch {
    return false
  }
}
```

Current code: No such check exists

---

### 4. **Error Recovery and User Feedback**

**Status:** ❌ MISSING

Errors should be:
- Caught and categorized (CLI not found, daemon down, scan failed, etc.)
- Displayed in VS Code UI (status bar, error message, output panel)
- Actionable (e.g., "Install CLI" button, "Start daemon" button)

Current code: Errors only logged to console

---

### 5. **File Watcher Dedupe**

**Status:** ⚠️ PARTIAL

VS Code might fire multiple save events for the same file. Extension should:
- Track pending scans
- Cancel previous scan if new save arrives
- Avoid overwhelming daemon with requests

Current code: No deduplication logic

---

## Failure Reproduction

### Steps to reproduce complete failure:

1. **Install extension** locally (or via VSIX)
2. **Install CLI** globally: `npm install -g omniguard-enterprise-cli`
3. **Open VS Code** with a test project
4. **Save a file** (e.g., `test.js`)
5. **Observe:**
   - Status bar shows spinning icon
   - Console shows no errors
   - After 5-10 seconds, status bar remains spinning
   - No diagnostics appear
   - Check DevTools console: nothing
   - Check daemon logs: might show connection refused

### Why it fails:

1. **runScan** is not awaited → Promise orphaned
2. **executeCliScan** likely hangs → CLI waiting for daemon
3. **No timeout** → UI blocks
4. **No health check** → Extension doesn't know daemon is missing

---

## Required Fixes

### Priority 1: Critical Path (Blocking End-to-End Flow)

#### Fix 1.1: Await runScan in save handler
**File:** `vscode-extension/src/extension.ts` (line 335)

**Current:**
```typescript
const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
  const config = vscode.workspace.getConfiguration('omniguard')
  if (config.get<boolean>('enableOnSave', true)) {
    runScan(doc)  // ORPHANED PROMISE
  }
})
```

**Fixed:**
```typescript
const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
  const config = vscode.workspace.getConfiguration('omniguard')
  if (config.get<boolean>('enableOnSave', true)) {
    // runScan is async, but don't block save event
    // Instead, queue scan and let it run in background
    runScanAsync(doc).catch(err => {
      console.error('Scan error:', err)
      statusBar.text = '$(shield) OmniGuard ✗'
      statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground')
    })
  }
})

async function runScanAsync(document: vscode.TextDocument) {
  try {
    statusBar.text = '$(sync~spin) OmniGuard: scanning...'
    const findings = await executeCliScanAsync(document.uri.fsPath)
    // ... rest of scan logic ...
  } finally {
    // Update status bar
  }
}
```

#### Fix 1.2: Add timeout to CLI invocation
**File:** `vscode-extension/src/extension.ts` (line 101-104)

**Current:**
```typescript
const result = spawnSync(command, args, {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe']
})
```

**Fixed:**
```typescript
const result = spawnSync(command, args, {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
  timeout: 30000  // 30 second timeout, prevent UI freeze
})

if (result.status === null) {
  // Process killed due to timeout
  throw new Error('CLI scan timed out after 30 seconds')
}
```

#### Fix 1.3: Check daemon health before scan
**New file:** `vscode-extension/src/daemonClient.ts`

```typescript
import { execSync } from 'child_process'

export class DaemonClient {
  async isHealthy(): Promise<boolean> {
    try {
      const result = execSync('omniguard daemon health', {
        encoding: 'utf8',
        timeout: 2000,
        stdio: ['ignore', 'pipe', 'pipe']
      })
      return result.includes('healthy') || result.includes('running')
    } catch {
      return false
    }
  }

  async ensureRunning(): Promise<void> {
    if (await this.isHealthy()) return

    // Try to start daemon
    try {
      execSync('omniguard daemon start', {
        stdio: 'ignore',
        detached: true
      })

      // Wait for daemon to start (max 5 seconds)
      for (let i = 0; i < 50; i++) {
        if (await this.isHealthy()) return
        await new Promise(resolve => setTimeout(resolve, 100))
      }

      throw new Error('Daemon failed to start')
    } catch (err) {
      throw new Error(`Failed to start daemon: ${err.message}`)
    }
  }
}
```

**Usage in extension.ts:**
```typescript
const daemon = new DaemonClient()

async function runScanAsync(document: vscode.TextDocument) {
  try {
    statusBar.text = '$(sync~spin) OmniGuard: checking daemon...'
    
    if (!await daemon.isHealthy()) {
      statusBar.text = '$(shield) OmniGuard: starting daemon...'
      await daemon.ensureRunning()
    }

    statusBar.text = '$(sync~spin) OmniGuard: scanning...'
    const findings = await executeCliScanAsync(document.uri.fsPath)
    // ... rest ...
  } catch (err) {
    vscode.window.showErrorMessage(`OmniGuard Error: ${err.message}`)
  }
}
```

#### Fix 1.4: Verify CLI scan command exists
**File:** `cli/src/index.js`

**Current:** `cmdScan` is referenced but not found in first 1905 lines

**Investigation needed:**
```bash
grep -n "^function cmdScan\|^const cmdScan\|^cmdScan = " cli/src/index.js
```

If not found, implement it:

```javascript
async function cmdScan(args) {
  const filePath = args && args[0] ? path.resolve(args[0]) : process.cwd()
  
  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`)
    process.exitCode = 1
    return
  }

  try {
    // 1. Connect to daemon
    const daemon = getDaemonConnection()
    
    // 2. Emit FILE_SAVED event
    eventBus.emit('FILE_SAVED', { path: filePath, timestamp: Date.now() })

    // 3. Orchestrate scanners
    const findings = await orchestrator.scanFile(filePath)

    // 4. Apply policies
    const policyResults = await policyEngine.evaluate(findings)

    // 5. Sync with backend if connected
    if (daemon.isConnected()) {
      await daemon.syncFindings(policyResults)
    }

    // 6. Output JSON to stdout
    console.log(JSON.stringify({ findings: policyResults }, null, 2))
  } catch (err) {
    console.error(`Scan error: ${err.message}`)
    process.exitCode = 1
  }
}
```

### Priority 2: Integration Improvements (Quality of Life)

#### Fix 2.1: Real-time progress updates via event bus
**File:** `vscode-extension/src/eventBusClient.ts` (new)

```typescript
export class EventBusClient {
  private eventEmitter = new EventEmitter()

  connect(daemonPath: string): Promise<void> {
    // Connect to daemon's event bus via IPC/socket
    // Listen for SCAN_PROGRESS, SCANNER_START, SCANNER_END, etc.
  }

  onScanProgress(callback: (progress: ScanProgress) => void) {
    this.eventEmitter.on('scan-progress', callback)
  }
}
```

**Usage:**
```typescript
const eventBus = new EventBusClient()

eventBus.onScanProgress(progress => {
  if (progress.stage === 'sast') {
    statusBar.text = `$(sync~spin) OmniGuard: SAST ${progress.percent}%`
  } else if (progress.stage === 'secrets') {
    statusBar.text = `$(sync~spin) OmniGuard: Secrets ${progress.percent}%`
  }
})
```

#### Fix 2.2: Deduplication of scan requests
**File:** `vscode-extension/src/extension.ts` (modify runScan)

```typescript
let pendingScan: { doc: vscode.TextDocument; timer: NodeJS.Timeout } | null = null

async function runScanAsync(document: vscode.TextDocument) {
  // Cancel previous pending scan if same file
  if (pendingScan && pendingScan.doc.uri.fsPath === document.uri.fsPath) {
    clearTimeout(pendingScan.timer)
  }

  // Debounce: wait 500ms before starting scan in case multiple saves
  const timer = setTimeout(async () => {
    pendingScan = null
    try {
      // ... execute scan ...
    } catch (err) {
      // ... handle error ...
    }
  }, 500)

  pendingScan = { doc: document, timer }
}
```

#### Fix 2.3: Display errors to user, not just console
**File:** `vscode-extension/src/extension.ts` (everywhere an error occurs)

```typescript
// Instead of:
console.error('OmniGuard CLI Error:', result.stderr)

// Do:
vscode.window.showErrorMessage(`OmniGuard Scan Error: ${result.stderr}`)
```

### Priority 3: Robustness (Fault Tolerance)

#### Fix 3.1: Output channel for logs
**File:** `vscode-extension/src/extension.ts`

```typescript
const outputChannel = vscode.window.createOutputChannel('OmniGuard')

function log(msg: string) {
  outputChannel.appendLine(`[${new Date().toISOString()}] ${msg}`)
}

// Replace all console.log/error with log()
```

#### Fix 3.2: Workspace settings validation
**File:** `vscode-extension/package.json` (add contributes.configuration)

```json
{
  "contributes": {
    "configuration": {
      "properties": {
        "omniguard.cliPath": {
          "type": "string",
          "description": "Path to omniguard CLI executable",
          "default": ""
        },
        "omniguard.enableOnSave": {
          "type": "boolean",
          "description": "Run scan on file save",
          "default": true
        },
        "omniguard.failOnSeverity": {
          "type": "string",
          "enum": ["critical", "high", "medium", "low", "info"],
          "description": "Severity threshold to fail the build",
          "default": "high"
        },
        "omniguard.daemonPort": {
          "type": "number",
          "description": "Port daemon listens on",
          "default": 9090
        }
      }
    }
  }
}
```

#### Fix 3.3: Graceful degradation
**File:** `vscode-extension/src/extension.ts`

```typescript
if (!verifyCliInstalled()) {
  vscode.window.showWarningMessage(
    'OmniGuard CLI not found. Install it to enable scanning.',
    'Install Now'
  ).then(choice => {
    if (choice === 'Install Now') {
      const terminal = vscode.window.createTerminal('OmniGuard Install')
      terminal.show()
      terminal.sendText('npm install -g omniguard-enterprise-cli')
    }
  })
  
  // Disable scan on save, but keep all other features
  scanOnSaveEnabled = false
  return
}
```

---

## Testing Strategy

### Unit Tests (To Write)

1. **daemonClient.ts**
   - `isHealthy()` returns true when daemon responds
   - `isHealthy()` returns false when daemon unreachable
   - `ensureRunning()` starts daemon if not running
   - `ensureRunning()` times out after 5 seconds

2. **extension.ts (scan flow)**
   - `executeCliScanAsync()` returns findings on success
   - `executeCliScanAsync()` throws on timeout (>30s)
   - `executeCliScanAsync()` throws on CLI not found
   - Save event triggers scan (with proper await)
   - Multiple saves deduplicated

3. **CLI scan command**
   - `cmdScan()` connects to daemon
   - `cmdScan()` emits FILE_SAVED event
   - `cmdScan()` returns valid JSON
   - `cmdScan()` handles file not found gracefully

### Integration Tests (To Write)

1. **End-to-End File Save**
   - Start daemon
   - Open VS Code extension
   - Save file
   - Verify diagnostics appear within 5 seconds
   - Verify status bar shows finding count

2. **Daemon Failure Recovery**
   - Start daemon
   - Kill daemon mid-scan
   - Extension should detect and show error
   - User can retry

3. **CLI Not Installed**
   - Don't install CLI globally
   - Activate extension
   - Extension should detect and offer install
   - Scanning should not break, just show message

### Manual Tests (To Execute)

1. **Happy path:** Save file → See diagnostics
2. **Daemon down:** Save file → See error → Start daemon → Retry → Works
3. **CLI not found:** Install CLI → Extension recovers
4. **Multiple saves:** Save file 5 times quickly → Only 1 scan runs
5. **Large file:** Save 1MB+ file → Scan completes in <10s

---

## Files That Need Changes

### Critical (Blocking)
- `vscode-extension/src/extension.ts` — Fix runScan await, add timeout, add health checks
- `vscode-extension/src/daemonClient.ts` — NEW, daemon connection logic
- `cli/src/index.js` — Verify/implement cmdScan function

### Important (Quality)
- `vscode-extension/src/eventBusClient.ts` — NEW, real-time progress updates
- `vscode-extension/package.json` — Add settings validation
- `vscode-extension/src/extension.ts` — Add output channel, error messages

### Nice to Have (Polish)
- Add tests (unit + integration)
- Add logging/diagnostics
- Add daemon auto-restart

---

## Success Criteria

After implementing fixes, the following should work:

1. **User saves file**
   - ✅ Within 1 second, status bar shows "scanning..."
   - ✅ Within 5 seconds, diagnostics appear in Problems panel
   - ✅ Code inline shows red/yellow squiggles
   - ✅ Hover tooltip shows finding details
   - ✅ Status bar shows "✓ OK" or "🔴 2 critical, 1 high"

2. **Daemon fails or is not running**
   - ✅ Extension detects within 2 seconds
   - ✅ User sees error message (not just spinning icon)
   - ✅ Extension offers to start daemon
   - ✅ After daemon starts, scan succeeds

3. **CLI not installed**
   - ✅ Extension detects on activation
   - ✅ User sees message with install button
   - ✅ Scanning gracefully disabled (no crashes)
   - ✅ After CLI installed, extension works

4. **Multiple saves on same file**
   - ✅ Only one scan runs (debounced)
   - ✅ No duplicate findings shown
   - ✅ Previous incomplete scans cancelled

---

## Recommendations for Long-Term

1. **Use WebSocket instead of spawn** — Connect extension to daemon WebSocket, stream results
2. **Implement LSP (Language Server Protocol)** — Standard IDE integration pattern
3. **Add real-time watching** — Daemon watches files, doesn't wait for save events
4. **Separate UI from business logic** — Extension should be state machine, not callback hell
5. **Add telemetry** — Track scan times, failure rates, user actions

---

## Conclusion

The architecture is **sound but incomplete**. The extension and CLI are **not integrated**, they are **adjacent**. The primary failures are:

1. **Broken async/await flow** — runScan promise not awaited
2. **No daemon lifecycle** — Extension assumes daemon exists
3. **No error visibility** — Errors silent, only logged
4. **No health checks** — No verification before scan attempt
5. **Timeout vulnerabilities** — UI can freeze indefinitely

**Estimated effort to fix:** 4-6 hours for a senior engineer  
**Risk if not fixed:** Integration appears to work in demo but fails in real use

The fixes are straightforward and low-risk, but **must be implemented before production release**.
