"use strict";
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
const http = __importStar(require("http"));
const https = __importStar(require("https"));
const SECRET_TOKEN_KEY = 'alpenguard.bearerToken';
function getOracleUrl() {
    const cfg = vscode.workspace.getConfiguration('alpenguard');
    return cfg.get('oracleUrl') ?? 'http://127.0.0.1:8787';
}
async function setOracleUrl(url) {
    const cfg = vscode.workspace.getConfiguration('alpenguard');
    await cfg.update('oracleUrl', url, vscode.ConfigurationTarget.Workspace);
}
async function getBearerToken(secrets) {
    return (await secrets.get(SECRET_TOKEN_KEY)) ?? '';
}
async function setBearerToken(secrets, token) {
    await secrets.store(SECRET_TOKEN_KEY, token);
}
async function clearBearerToken(secrets) {
    await secrets.delete(SECRET_TOKEN_KEY);
}
function isSafeHttpUrl(input) {
    try {
        const u = new URL(input);
        return u.protocol === 'http:' || u.protocol === 'https:';
    }
    catch {
        return false;
    }
}
function requestJson(url, opts) {
    return new Promise((resolve) => {
        let u;
        try {
            u = new URL(url);
        }
        catch {
            resolve({ ok: false, status: 0, error: 'invalid_url' });
            return;
        }
        const isHttps = u.protocol === 'https:';
        const lib = isHttps ? https : http;
        const reqBody = opts.body !== undefined ? Buffer.from(JSON.stringify(opts.body), 'utf8') : undefined;
        const req = lib.request({
            method: opts.method,
            hostname: u.hostname,
            port: u.port ? parseInt(u.port, 10) : isHttps ? 443 : 80,
            path: `${u.pathname}${u.search}`,
            headers: {
                ...(opts.headers ?? {}),
                ...(reqBody ? { 'content-type': 'application/json', 'content-length': String(reqBody.length) } : {}),
            },
        }, (res) => {
            const chunks = [];
            res.on('data', (d) => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
            res.on('end', () => {
                const raw = Buffer.concat(chunks).toString('utf8');
                const status = res.statusCode ?? 0;
                if (status < 200 || status >= 300) {
                    resolve({ ok: false, status, error: raw || `http_${status}` });
                    return;
                }
                try {
                    const parsed = raw ? JSON.parse(raw) : undefined;
                    resolve({ ok: true, status, data: parsed });
                }
                catch {
                    resolve({ ok: false, status, error: 'invalid_json' });
                }
            });
        });
        req.on('error', (e) => resolve({ ok: false, status: 0, error: String(e) }));
        req.setTimeout(opts.timeoutMs, () => {
            req.destroy(new Error('timeout'));
        });
        if (reqBody)
            req.write(reqBody);
        req.end();
    });
}
function decodeB64Preview(b64) {
    try {
        if (!b64)
            return '';
        if (b64.length > 64_000)
            return '';
        const bytes = Buffer.from(b64, 'base64');
        const txt = bytes.toString('utf8');
        return txt.length > 4000 ? `${txt.slice(0, 4000)}\n…(truncated)…` : txt;
    }
    catch {
        return '';
    }
}
function nonce() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let out = '';
    for (let i = 0; i < 32; i++)
        out += alphabet[Math.floor(Math.random() * alphabet.length)];
    return out;
}
function getWebviewHtml(webview, extensionUri) {
    const n = nonce();
    const csp = [
        `default-src 'none';`,
        `img-src ${webview.cspSource} data:;`,
        `style-src ${webview.cspSource} 'unsafe-inline';`,
        `script-src 'nonce-${n}';`,
    ].join(' ');
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>AlpenGuard Trace Explorer</title>
</head>
<body>
  <div style="font-family: system-ui, -apple-system, Segoe UI, sans-serif; padding: 12px;">
    <h2 style="margin: 0 0 8px 0;">AlpenGuard Trace Explorer</h2>

    <div style="display: grid; grid-template-columns: 1fr; gap: 10px; max-width: 960px;">
      <div style="border: 1px solid #ddd; border-radius: 10px; padding: 12px;">
        <div style="font-weight: 700; margin-bottom: 8px;">Connection</div>
        <div style="display:flex; gap: 8px; align-items:center; flex-wrap: wrap;">
          <button id="pingBtn">Ping Oracle</button>
          <button id="listBtn">List traces</button>
          <button id="refreshStatusBtn">Refresh status</button>
          <span id="statusText" style="opacity: 0.8;"></span>
        </div>
        <div style="margin-top: 10px; display:flex; gap: 8px; align-items:center; flex-wrap: wrap;">
          <label style="min-width: 90px; opacity: 0.8;">Oracle URL</label>
          <input id="oracleUrl" style="flex:1; min-width: 320px; padding: 6px;" spellcheck="false" />
          <button id="saveOracleUrlBtn">Save</button>
        </div>
        <div style="margin-top: 10px; opacity: 0.85;">
          Token: <span id="tokenStatus">unknown</span>
          <div style="margin-top: 6px;">
            Set/clear token via the Command Palette:
            <code>AlpenGuard: Set Bearer Token</code>
          </div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 10px;">
        <div style="border: 1px solid #ddd; border-radius: 10px; padding: 12px; overflow:auto;">
          <div style="font-weight: 700; margin-bottom: 8px;">Traces</div>
          <div id="traceList" style="display:grid; gap: 6px;"></div>
        </div>
        <div style="border: 1px solid #ddd; border-radius: 10px; padding: 12px; overflow:auto;">
          <div style="font-weight: 700; margin-bottom: 8px;">Payload Preview</div>
          <pre id="payloadPreview" style="white-space: pre-wrap; word-break: break-word; margin: 0;"></pre>
        </div>
      </div>
    </div>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();

    const pingBtn = document.getElementById('pingBtn');
    const listBtn = document.getElementById('listBtn');
    const refreshStatusBtn = document.getElementById('refreshStatusBtn');
    const statusText = document.getElementById('statusText');
    const oracleUrlInput = document.getElementById('oracleUrl');
    const saveOracleUrlBtn = document.getElementById('saveOracleUrlBtn');
    const tokenStatus = document.getElementById('tokenStatus');
    const traceList = document.getElementById('traceList');
    const payloadPreview = document.getElementById('payloadPreview');

    function setStatusText(t) { statusText.textContent = t; }

    pingBtn.addEventListener('click', () => vscode.postMessage({ type: 'ping' }));
    listBtn.addEventListener('click', () => vscode.postMessage({ type: 'list' }));
    refreshStatusBtn.addEventListener('click', () => vscode.postMessage({ type: 'getStatus' }));

    saveOracleUrlBtn.addEventListener('click', () => {
      const v = String(oracleUrlInput.value || '').trim();
      vscode.postMessage({ type: 'setOracleUrl', oracleUrl: v });
    });

    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (!msg || typeof msg.type !== 'string') return;

      if (msg.type === 'status') {
        oracleUrlInput.value = msg.oracleUrl || '';
        tokenStatus.textContent = msg.tokenPresent ? 'configured' : 'not set';
        return;
      }

      if (msg.type === 'pong') {
        if (msg.ok) {
          const httpPart = msg.httpStatus ? (' (HTTP ' + msg.httpStatus + ')') : '';
          const latPart = (typeof msg.latencyMs === 'number') ? (' · ' + msg.latencyMs + 'ms') : '';
          setStatusText('healthy' + httpPart + latPart);
        } else {
          const httpPart = msg.httpStatus ? (' (HTTP ' + msg.httpStatus + ')') : '';
          const errPart = msg.error ? (' · ' + msg.error) : '';
          setStatusText('error' + httpPart + errPart);
        }
        return;
      }

      if (msg.type === 'traceList') {
        traceList.innerHTML = '';
        payloadPreview.textContent = '';
        if (!msg.ok) {
          setStatusText('list error' + (msg.error ? (' · ' + msg.error) : ''));
          return;
        }
        for (const t of (msg.items || [])) {
          const btn = document.createElement('button');
          btn.textContent = String(t.event_type) + ' · ' + String(t.agent_id) + ' · ' + new Date(t.ts_unix_ms).toLocaleString();
          btn.style.textAlign = 'left';
          btn.addEventListener('click', () => vscode.postMessage({ type: 'get', trace_id: t.trace_id, span_id: t.span_id }));
          traceList.appendChild(btn);
        }
        setStatusText('listed ' + String((msg.items || []).length));
        return;
      }

      if (msg.type === 'traceGet') {
        if (!msg.ok) {
          payloadPreview.textContent = '';
          setStatusText('get error' + (msg.error ? (' · ' + msg.error) : ''));
          return;
        }
        payloadPreview.textContent = msg.payloadPreview || '';
        setStatusText('payload loaded');
        return;
      }

      if (msg.type === 'toast') {
        setStatusText(msg.message || '');
        return;
      }
    });

    vscode.postMessage({ type: 'getStatus' });
  </script>
</body>
</html>`;
}
function activate(context) {
    const openTraceExplorer = vscode.commands.registerCommand('alpenguard.openTraceExplorer', async () => {
        const panel = vscode.window.createWebviewPanel('alpenguard.traceExplorer', 'AlpenGuard Trace Explorer', vscode.ViewColumn.One, { enableScripts: true });
        panel.webview.html = getWebviewHtml(panel.webview, context.extensionUri);
        const postStatus = async () => {
            const oracleUrl = getOracleUrl();
            const token = await getBearerToken(context.secrets);
            const msg = {
                type: 'status',
                oracleUrl,
                tokenPresent: Boolean(token.trim()),
            };
            panel.webview.postMessage(msg);
        };
        await postStatus();
        panel.webview.onDidReceiveMessage(async (raw) => {
            const msg = raw;
            if (!msg || typeof msg.type !== 'string')
                return;
            if (msg.type === 'getStatus') {
                await postStatus();
                return;
            }
            if (msg.type === 'setOracleUrl') {
                const url = String(msg.oracleUrl ?? '').trim();
                if (!isSafeHttpUrl(url)) {
                    panel.webview.postMessage({ type: 'toast', level: 'error', message: 'Invalid Oracle URL' });
                    return;
                }
                await setOracleUrl(url);
                await postStatus();
                panel.webview.postMessage({ type: 'toast', level: 'info', message: 'Oracle URL saved (workspace)' });
                return;
            }
            const oracleUrl = getOracleUrl();
            const token = (await getBearerToken(context.secrets)).trim();
            const authHeader = token ? { Authorization: `Bearer ${token}` } : undefined;
            if (msg.type === 'ping') {
                const t0 = Date.now();
                const r = await requestJson(`${oracleUrl}/healthz`, { method: 'GET', headers: authHeader, timeoutMs: 10_000 });
                const latencyMs = Date.now() - t0;
                panel.webview.postMessage({
                    type: 'pong',
                    ok: r.ok,
                    httpStatus: r.status,
                    latencyMs,
                    error: r.ok ? undefined : r.error,
                });
                return;
            }
            if (msg.type === 'list') {
                const r = await requestJson(`${oracleUrl}/v1/traces:list`, {
                    method: 'GET',
                    headers: authHeader,
                    timeoutMs: 10_000,
                });
                const maxItems = vscode.workspace.getConfiguration('alpenguard').get('traceExplorer.maxItems') ?? 50;
                const items = Array.isArray(r.data?.items) ? r.data.items.slice(0, Math.max(1, Math.min(500, maxItems))) : [];
                panel.webview.postMessage({
                    type: 'traceList',
                    ok: r.ok,
                    items: r.ok ? items : [],
                    error: r.ok ? undefined : r.error,
                });
                return;
            }
            if (msg.type === 'get') {
                const traceId = String(msg.trace_id ?? '');
                const spanId = String(msg.span_id ?? '');
                if (!traceId || !spanId) {
                    panel.webview.postMessage({ type: 'traceGet', ok: false, payloadPreview: '', error: 'invalid_input' });
                    return;
                }
                const r = await requestJson(`${oracleUrl}/v1/traces:get`, {
                    method: 'POST',
                    headers: authHeader,
                    body: { trace_id: traceId, span_id: spanId },
                    timeoutMs: 15_000,
                });
                const payloadPreview = r.ok && r.data ? decodeB64Preview(r.data.payload_b64) : '';
                panel.webview.postMessage({
                    type: 'traceGet',
                    ok: r.ok,
                    payloadPreview,
                    trace: r.ok ? r.data?.trace : undefined,
                    error: r.ok ? undefined : r.error,
                });
                return;
            }
        });
    });
    const setTokenCmd = vscode.commands.registerCommand('alpenguard.setBearerToken', async () => {
        const token = await vscode.window.showInputBox({
            title: 'AlpenGuard Bearer Token',
            prompt: 'Paste an OIDC access token / identity token. Stored securely in VS Code SecretStorage.',
            password: true,
            ignoreFocusOut: true,
        });
        if (token === undefined)
            return;
        await setBearerToken(context.secrets, token.trim());
        vscode.window.showInformationMessage('AlpenGuard token stored.');
    });
    const clearTokenCmd = vscode.commands.registerCommand('alpenguard.clearBearerToken', async () => {
        await clearBearerToken(context.secrets);
        vscode.window.showInformationMessage('AlpenGuard token cleared.');
    });
    const pingCmd = vscode.commands.registerCommand('alpenguard.pingOracle', async () => {
        const oracleUrl = getOracleUrl();
        const token = (await getBearerToken(context.secrets)).trim();
        const authHeader = token ? { Authorization: `Bearer ${token}` } : undefined;
        const t0 = Date.now();
        const r = await requestJson(`${oracleUrl}/healthz`, { method: 'GET', headers: authHeader, timeoutMs: 10_000 });
        const latencyMs = Date.now() - t0;
        if (r.ok) {
            vscode.window.showInformationMessage(`AlpenGuard Oracle healthy (HTTP ${r.status}, ${latencyMs}ms)`);
        }
        else {
            vscode.window.showErrorMessage(`AlpenGuard Oracle ping failed (HTTP ${r.status}): ${r.error ?? 'error'}`);
        }
    });
    context.subscriptions.push(openTraceExplorer, setTokenCmd, clearTokenCmd, pingCmd);
}
function deactivate() { }
