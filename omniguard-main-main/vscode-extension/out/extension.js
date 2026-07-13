"use strict";
// OmniGuard VS Code Extension — UI Layer over CLI
// Features: async scanning with timeout, inline diagnostics, tree view, hover, output channel
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const http = __importStar(require("http"));
// ─── Output Channel (structured logs for Extension → CLI → Daemon chain) ─────
let outputChannel;
function log(msg) {
    const ts = new Date().toISOString();
    outputChannel?.appendLine(`[${ts}] ${msg}`);
}
// ─── Helper: Detect and resolve CLI command ───────────────────────────────────
function getCliCommand() {
    const config = vscode.workspace.getConfiguration('omniguard');
    const customPath = config.get('cliPath', '').trim();
    if (customPath) {
        if (customPath.endsWith('.js')) {
            return { cmd: 'node', args: [customPath] };
        }
        return { cmd: customPath, args: [] };
    }
    // 1. Check system PATH
    try {
        const checkCmd = process.platform === 'win32' ? 'where omniguard' : 'which omniguard';
        (0, child_process_1.execSync)(checkCmd, { stdio: 'ignore', timeout: 3000 });
        log('[CLI Discovery] Found omniguard in system PATH');
        return { cmd: process.platform === 'win32' ? 'omniguard.cmd' : 'omniguard', args: [] };
    }
    catch { }
    // 2. npm global bin (handles npm link and global installs on all platforms)
    try {
        const npmBin = (0, child_process_1.execSync)('npm bin -g', { encoding: 'utf8', timeout: 3000 }).trim();
        const ext = process.platform === 'win32' ? '.cmd' : '';
        const globalPath = path.join(npmBin, `omniguard${ext}`);
        if (fs.existsSync(globalPath)) {
            log(`[CLI Discovery] Found via npm global bin: ${globalPath}`);
            return { cmd: globalPath, args: [] };
        }
    }
    catch { }
    // 3. Local workspace peer CLI (dev mode)
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
        for (const folder of workspaceFolders) {
            const candidates = [
                path.join(folder.uri.fsPath, 'cli', 'src', 'index.js'),
                path.join(folder.uri.fsPath, '..', 'cli', 'src', 'index.js'),
                path.join(folder.uri.fsPath, 'omniguard-main-main', 'cli', 'src', 'index.js')
            ];
            for (const c of candidates) {
                if (fs.existsSync(c)) {
                    log(`[CLI Discovery] Found local dev CLI: ${c}`);
                    return { cmd: 'node', args: [c] };
                }
            }
        }
    }
    // 4. npx fallback
    log('[CLI Discovery] Falling back to npx @omniguard/cli');
    return { cmd: 'npx', args: ['@omniguard/cli'] };
}
async function verifyCliInstalled() {
    const { cmd, args } = getCliCommand();
    return new Promise(resolve => {
        const proc = (0, child_process_1.spawn)(cmd, [...args, 'version'], {
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 5000,
            shell: process.platform === 'win32'
        });
        let out = '';
        proc.stdout.on('data', (d) => { out += d.toString(); });
        proc.on('close', code => {
            const ok = code === 0 && out.toLowerCase().includes('omniguard');
            log(`[CLI Verify] cmd="${cmd}" result=${ok ? 'ok' : 'not found'} output="${out.trim()}"`);
            resolve(ok);
        });
        proc.on('error', () => resolve(false));
    });
}
function promptInstallCli() {
    vscode.window.showErrorMessage('OmniGuard CLI is required but not found in PATH.', 'Install Globally (npm)', 'Show Output').then(choice => {
        if (choice === 'Install Globally (npm)') {
            const terminal = vscode.window.createTerminal('OmniGuard Installation');
            terminal.show();
            terminal.sendText('npm install -g omniguard-enterprise-cli');
        }
        else if (choice === 'Show Output') {
            outputChannel.show();
        }
    });
}
const SEVERITY_ORDER = {
    critical: 4, high: 3, medium: 2, low: 1, info: 0
};
// ─── Async scan via CLI (spawn with timeout) ──────────────────────────────────
function executeCliScan(filePath) {
    const { cmd, args } = getCliCommand();
    const config = vscode.workspace.getConfiguration('omniguard');
    const timeoutMs = config.get('scanTimeout', 30000);
    log(`[Scan] Executing: ${cmd} ${[...args, 'scan', '--json', filePath].join(' ')}`);
    return new Promise(resolve => {
        let stdout = '';
        let stderr = '';
        let settled = false;
        const proc = (0, child_process_1.spawn)(cmd, [...args, 'scan', '--json', filePath], {
            stdio: ['ignore', 'pipe', 'pipe'],
            env: { ...process.env, OMNIGUARD_AUDIT_MODE: undefined },
            shell: process.platform === 'win32'
        });
        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                proc.kill();
                log(`[Scan] TIMEOUT after ${timeoutMs}ms for ${filePath}`);
                resolve([]);
            }
        }, timeoutMs);
        proc.stdout.on('data', (d) => { stdout += d.toString(); });
        proc.stderr.on('data', (d) => { stderr += d.toString(); });
        proc.on('close', code => {
            clearTimeout(timer);
            if (settled)
                return;
            settled = true;
            if (stderr.trim())
                log(`[Scan] CLI stderr: ${stderr.trim()}`);
            log(`[Scan] CLI exited code=${code} stdout_len=${stdout.length}`);
            try {
                const parsed = JSON.parse(stdout);
                const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
                log(`[Scan] Parsed ${findings.length} finding(s) from ${filePath}`);
                resolve(findings);
            }
            catch {
                // stdout may contain progress lines before JSON — try to extract last JSON object
                const jsonMatch = stdout.match(/(\{[\s\S]*\})\s*$/);
                if (jsonMatch) {
                    try {
                        const parsed = JSON.parse(jsonMatch[1]);
                        const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
                        resolve(findings);
                        return;
                    }
                    catch { }
                }
                log(`[Scan] Failed to parse JSON output: ${stdout.substring(0, 200)}`);
                resolve([]);
            }
        });
        proc.on('error', err => {
            clearTimeout(timer);
            if (!settled) {
                settled = true;
                log(`[Scan] Spawn error: ${err.message}`);
                resolve([]);
            }
        });
    });
}
// ─── Daemon health check ──────────────────────────────────────────────────────
function checkDaemonRunning() {
    const port = vscode.workspace.getConfiguration('omniguard').get('daemonPort', 5175);
    return new Promise(resolve => {
        const req = http.request({ hostname: '127.0.0.1', port, path: '/healthz', method: 'GET', timeout: 2000 }, res => {
            resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.end();
    });
}
// ─── Diagnostics ─────────────────────────────────────────────────────────────
function findingToDiagnostic(finding, document, failOn) {
    const line = Math.max(0, (finding.line_start || 1) - 1);
    const safeLine = Math.min(line, document.lineCount - 1);
    const lineText = document.lineAt(safeLine).text;
    const start = Math.max(0, lineText.search(/\S/));
    const range = new vscode.Range(new vscode.Position(safeLine, start), new vscode.Position(safeLine, lineText.length));
    const threshold = SEVERITY_ORDER[failOn] ?? 3;
    const isError = (SEVERITY_ORDER[finding.severity] ?? 0) >= threshold;
    const diag = new vscode.Diagnostic(range, `[OmniGuard ${finding.severity.toUpperCase()}] ${finding.title}${finding.evidence ? ` — ${finding.evidence}` : ''}`, isError ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning);
    diag.source = 'OmniGuard';
    diag.code = finding.rule_id;
    return diag;
}
// ─── Hover Provider ───────────────────────────────────────────────────────────
class OmniGuardHoverProvider {
    constructor(findingMap) {
        this.findingMap = findingMap;
    }
    provideHover(document, position) {
        const findings = this.findingMap.get(document.uri.fsPath);
        if (!findings)
            return null;
        const matching = findings.filter(f => ((f.line_start || 1) - 1) === position.line);
        if (!matching.length)
            return null;
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        for (const f of matching) {
            md.appendMarkdown(`### 🛡️ OmniGuard Finding: ${f.title}\n\n`);
            md.appendMarkdown(`**Severity:** \`${f.severity.toUpperCase()}\` | **Rule:** \`${f.rule_id}\` | **Scanner:** \`${f.scanner}\`\n\n`);
            if (f.evidence)
                md.appendMarkdown(`**Evidence:** \`${f.evidence}\`\n\n`);
            if (f.ai_explanation)
                md.appendMarkdown(`**AI Analysis:** ${f.ai_explanation.substring(0, 300)}\n\n`);
            md.appendMarkdown(`---\n`);
            const id = f.id || f.rule_id;
            md.appendMarkdown(`[$(lightbulb) Explain](command:omniguard.explain?${encodeURIComponent(JSON.stringify(id))}) | ` +
                `[$(tools) Fix](command:omniguard.fixFinding?${encodeURIComponent(JSON.stringify(id))}) | ` +
                `[$(bug) Jira](command:omniguard.createJira?${encodeURIComponent(JSON.stringify(id))}) | ` +
                `[$(server) ServiceNow](command:omniguard.createServiceNow?${encodeURIComponent(JSON.stringify(id))})\n`);
        }
        return new vscode.Hover(md);
    }
}
// ─── CodeLens Provider ────────────────────────────────────────────────────────
class OmniGuardCodeLensProvider {
    constructor(findingMap) {
        this.findingMap = findingMap;
        this._onDidChange = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChange.event;
    }
    refresh() { this._onDidChange.fire(); }
    provideCodeLenses(document) {
        const findings = this.findingMap.get(document.uri.fsPath);
        if (!findings?.length)
            return [];
        return findings.map(f => {
            const line = Math.max(0, (f.line_start || 1) - 1);
            const range = new vscode.Range(line, 0, line, 0);
            return new vscode.CodeLens(range, {
                title: `🛡️ ${f.severity.toUpperCase()}: ${f.rule_id} — Click to fix`,
                command: 'omniguard.fixFinding',
                arguments: [f.id || f.rule_id]
            });
        });
    }
}
// ─── Findings Panel Tree View ─────────────────────────────────────────────────
class FindingItem extends vscode.TreeItem {
    constructor(finding, uri) {
        super(`[${finding.severity.toUpperCase()}] ${finding.title}`, vscode.TreeItemCollapsibleState.None);
        this.finding = finding;
        this.uri = uri;
        this.description = `${path.basename(uri.fsPath)}:${finding.line_start}`;
        this.tooltip = finding.evidence || finding.title;
        this.iconPath = new vscode.ThemeIcon(finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning');
        this.command = {
            command: 'vscode.open',
            arguments: [
                uri,
                { selection: new vscode.Range(Math.max(0, (finding.line_start || 1) - 1), 0, Math.max(0, (finding.line_start || 1) - 1), 0) }
            ],
            title: 'Go to Finding'
        };
    }
}
class OmniGuardTreeProvider {
    constructor() {
        this._onDidChange = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChange.event;
        this.findingMap = new Map();
    }
    update(uri, findings) {
        this.findingMap.set(uri.fsPath, { uri, findings });
        this._onDidChange.fire();
    }
    clearAll() {
        this.findingMap.clear();
        this._onDidChange.fire();
    }
    getTreeItem(element) { return element; }
    getChildren() {
        const items = [];
        for (const { uri, findings } of this.findingMap.values()) {
            for (const f of findings)
                items.push(new FindingItem(f, uri));
        }
        return items.sort((a, b) => (SEVERITY_ORDER[b.finding.severity] ?? 0) - (SEVERITY_ORDER[a.finding.severity] ?? 0));
    }
}
// ─── Extension Activation ─────────────────────────────────────────────────────
function activate(context) {
    outputChannel = vscode.window.createOutputChannel('OmniGuard');
    const diagCollection = vscode.languages.createDiagnosticCollection('omniguard');
    const findingMap = new Map();
    const treeProvider = new OmniGuardTreeProvider();
    const codeLensProvider = new OmniGuardCodeLensProvider(findingMap);
    // Status Bar
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(shield) OmniGuard';
    statusBar.tooltip = 'OmniGuard Security Scanner';
    statusBar.command = 'omniguard.showFindings';
    statusBar.show();
    // Tree view
    const treeView = vscode.window.createTreeView('omniguardFindings', { treeDataProvider: treeProvider });
    // Hover provider
    const hoverProvider = vscode.languages.registerHoverProvider({ scheme: 'file' }, new OmniGuardHoverProvider(findingMap));
    // CodeLens provider
    const codeLensDisposable = vscode.languages.registerCodeLensProvider({ scheme: 'file' }, codeLensProvider);
    context.subscriptions.push(outputChannel, diagCollection, statusBar, treeView, hoverProvider, codeLensDisposable);
    log('[Extension] OmniGuard activated');
    // Async CLI verify — does not block activation
    verifyCliInstalled().then(ok => {
        if (!ok) {
            log('[Extension] CLI not found — prompting user');
            promptInstallCli();
        }
        else {
            log('[Extension] CLI verified OK');
        }
    });
    // Async daemon status check — logged only
    checkDaemonRunning().then(running => {
        log(`[Daemon] Status: ${running ? 'RUNNING on port 5175' : 'NOT running (local CLI scan will be used)'}`);
        if (!running) {
            statusBar.tooltip = 'OmniGuard — Daemon offline (local scan mode)';
        }
    });
    // ─── Debounce helper ────────────────────────────────────────────────────────
    const debounceTimers = new Map();
    function debounce(key, fn, ms) {
        const existing = debounceTimers.get(key);
        if (existing)
            clearTimeout(existing);
        debounceTimers.set(key, setTimeout(() => {
            debounceTimers.delete(key);
            fn();
        }, ms));
    }
    // ─── Core scan function ─────────────────────────────────────────────────────
    async function runScan(document) {
        const filePath = document.uri.fsPath;
        const config = vscode.workspace.getConfiguration('omniguard');
        // Respect exclude patterns
        const excludePatterns = config.get('excludePatterns', [
            '**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**'
        ]);
        for (const pattern of excludePatterns) {
            if (vscode.languages.match({ pattern }, document) > 0) {
                log(`[Scan] Skipping excluded file: ${filePath}`);
                return;
            }
        }
        statusBar.text = '$(sync~spin) OmniGuard: scanning...';
        log(`[Scan] Starting scan: ${filePath}`);
        try {
            const findings = await executeCliScan(filePath);
            findingMap.set(filePath, findings);
            treeProvider.update(document.uri, findings);
            codeLensProvider.refresh();
            const failOn = config.get('failOnSeverity', 'high');
            const diags = findings.map(f => findingToDiagnostic(f, document, failOn));
            diagCollection.set(document.uri, diags);
            const crit = findings.filter(f => f.severity === 'critical').length;
            const high = findings.filter(f => f.severity === 'high').length;
            const total = findings.length;
            if (total === 0) {
                statusBar.text = '$(shield) OmniGuard ✓';
                statusBar.backgroundColor = undefined;
                log(`[Scan] Clean: ${filePath}`);
            }
            else {
                statusBar.text = `$(shield) OmniGuard (${crit}C/${high}H)`;
                statusBar.backgroundColor = crit > 0
                    ? new vscode.ThemeColor('statusBarItem.errorBackground')
                    : new vscode.ThemeColor('statusBarItem.warningBackground');
                log(`[Scan] ${total} finding(s): ${crit} critical, ${high} high in ${filePath}`);
                // Notify user for critical/high findings
                if (crit > 0 || high > 0) {
                    vscode.window.showWarningMessage(`OmniGuard: ${crit} critical, ${high} high severity issue(s) found in ${path.basename(filePath)}`, 'Show Details').then(choice => {
                        if (choice === 'Show Details') {
                            vscode.commands.executeCommand('omniguardFindings.focus');
                        }
                    });
                }
            }
        }
        catch (err) {
            statusBar.text = '$(shield) OmniGuard !';
            log(`[Scan] Error scanning ${filePath}: ${err.message}`);
            vscode.window.showErrorMessage(`OmniGuard scan error: ${err.message}`, 'Show Logs').then(c => {
                if (c === 'Show Logs')
                    outputChannel.show();
            });
        }
    }
    // ─── Commands ────────────────────────────────────────────────────────────────
    const cmdScanFile = vscode.commands.registerCommand('omniguard.scanFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            runScan(editor.document);
        }
        else {
            vscode.window.showInformationMessage('Open a file to run an OmniGuard scan.');
        }
    });
    const cmdScanWorkspace = vscode.commands.registerCommand('omniguard.scanWorkspace', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders?.length) {
            vscode.window.showInformationMessage('No workspace folder open.');
            return;
        }
        const { cmd, args } = getCliCommand();
        const workspacePath = folders[0].uri.fsPath;
        log(`[Scan Workspace] Scanning: ${workspacePath}`);
        statusBar.text = '$(sync~spin) OmniGuard: scanning workspace...';
        const terminal = vscode.window.createTerminal({
            name: 'OmniGuard Workspace Scan',
            cwd: workspacePath
        });
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" scan --json .`
            : `${cmd} scan --json .`;
        terminal.sendText(scanCmd);
        statusBar.text = '$(shield) OmniGuard';
    });
    const cmdExplain = vscode.commands.registerCommand('omniguard.explain', (findingId) => {
        const id = Array.isArray(findingId) ? findingId[0] : findingId;
        const { cmd, args } = getCliCommand();
        const editor = vscode.window.activeTextEditor;
        const filePath = editor?.document?.uri?.fsPath || '';
        const terminal = vscode.window.createTerminal('OmniGuard: Explain Finding');
        terminal.show();
        const explainCmd = cmd === 'node'
            ? `node "${args[0]}" explain ${id}${filePath ? ` "${filePath}"` : ''}`
            : `${cmd} explain ${id}${filePath ? ` "${filePath}"` : ''}`;
        terminal.sendText(explainCmd);
        log(`[Command] explain finding: ${id} file=${filePath}`);
    });
    const cmdFixFinding = vscode.commands.registerCommand('omniguard.fixFinding', async (findingId) => {
        const id = Array.isArray(findingId) ? findingId[0] : findingId;
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showInformationMessage('Open the file with the finding to apply a fix.');
            return;
        }
        const filePath = editor.document.uri.fsPath;
        const { cmd, args } = getCliCommand();
        log(`[Command] fix finding: ${id} in ${filePath}`);
        const terminal = vscode.window.createTerminal('OmniGuard: AI Fix');
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" fix ${id} "${filePath}"`
            : `${cmd} fix ${id} "${filePath}"`;
        terminal.sendText(scanCmd);
    });
    const cmdCreateJira = vscode.commands.registerCommand('omniguard.createJira', (findingId) => {
        const id = Array.isArray(findingId) ? findingId[0] : findingId;
        const { cmd, args } = getCliCommand();
        const terminal = vscode.window.createTerminal('OmniGuard: Create Jira Ticket');
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" integrations jira create ${id}`
            : `${cmd} integrations jira create ${id}`;
        terminal.sendText(scanCmd);
        log(`[Command] create Jira for finding: ${id}`);
    });
    const cmdCreateServiceNow = vscode.commands.registerCommand('omniguard.createServiceNow', (findingId) => {
        const id = Array.isArray(findingId) ? findingId[0] : findingId;
        const { cmd, args } = getCliCommand();
        const terminal = vscode.window.createTerminal('OmniGuard: Create ServiceNow Incident');
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" integrations servicenow incident ${id}`
            : `${cmd} integrations servicenow incident ${id}`;
        terminal.sendText(scanCmd);
        log(`[Command] create ServiceNow for finding: ${id}`);
    });
    const cmdConfigure = vscode.commands.registerCommand('omniguard.configure', () => {
        const { cmd, args } = getCliCommand();
        const terminal = vscode.window.createTerminal('OmniGuard: Configure');
        terminal.show();
        const loginCmd = cmd === 'node'
            ? `node "${args[0]}" login`
            : `${cmd} login`;
        terminal.sendText(loginCmd);
        log('[Command] configure/login');
    });
    const cmdClear = vscode.commands.registerCommand('omniguard.clearDiagnostics', () => {
        diagCollection.clear();
        findingMap.clear();
        treeProvider.clearAll();
        codeLensProvider.refresh();
        statusBar.text = '$(shield) OmniGuard';
        statusBar.backgroundColor = undefined;
        log('[Command] diagnostics cleared');
    });
    const cmdShow = vscode.commands.registerCommand('omniguard.showFindings', () => {
        vscode.commands.executeCommand('omniguardFindings.focus');
        log('[Command] show findings panel');
    });
    const cmdNexusGraph = vscode.commands.registerCommand('omniguard.nexusGraph', () => {
        const { cmd, args } = getCliCommand();
        const terminal = vscode.window.createTerminal('OmniGuard: Nexus Graph');
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" nexus graph`
            : `${cmd} nexus graph`;
        terminal.sendText(scanCmd);
        log('[Command] nexus graph');
    });
    const cmdAgentMap = vscode.commands.registerCommand('omniguard.agentMap', () => {
        const folders = vscode.workspace.workspaceFolders;
        const cwd = folders?.[0]?.uri?.fsPath || '.';
        const { cmd, args } = getCliCommand();
        const terminal = vscode.window.createTerminal({ name: 'OmniGuard: System Mapping Agent', cwd });
        terminal.show();
        const scanCmd = cmd === 'node'
            ? `node "${args[0]}" agent map`
            : `${cmd} agent map`;
        terminal.sendText(scanCmd);
        log('[Command] agent map');
    });
    const cmdShowLogs = vscode.commands.registerCommand('omniguard.showLogs', () => {
        outputChannel.show();
    });
    // ─── On-save trigger with debounce ──────────────────────────────────────────
    const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
        const config = vscode.workspace.getConfiguration('omniguard');
        if (!config.get('enableOnSave', true))
            return;
        const delay = config.get('scanDelay', 800);
        debounce(doc.uri.fsPath, () => runScan(doc), delay);
    });
    // ─── On-type trigger (optional, debounced) ──────────────────────────────────
    const onType = vscode.workspace.onDidChangeTextDocument(event => {
        const config = vscode.workspace.getConfiguration('omniguard');
        if (!config.get('enableOnType', false))
            return;
        if (event.contentChanges.length === 0)
            return;
        const doc = event.document;
        debounce(doc.uri.fsPath + ':type', () => runScan(doc), 2000);
    });
    context.subscriptions.push(cmdScanFile, cmdScanWorkspace, cmdExplain, cmdFixFinding, cmdCreateJira, cmdCreateServiceNow, cmdConfigure, cmdClear, cmdShow, cmdNexusGraph, cmdAgentMap, cmdShowLogs, onSave, onType);
    log('[Extension] All commands and listeners registered');
}
function deactivate() {
    log('[Extension] Deactivated');
}
//# sourceMappingURL=extension.js.map