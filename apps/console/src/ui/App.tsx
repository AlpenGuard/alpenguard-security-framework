import React, { useMemo, useState } from 'react';

type Route = 'dashboard' | 'traces' | 'redteam' | 'payments' | 'settings';

function NavItem(props: { label: string; route: Route; active: boolean; onClick: (r: Route) => void }) {
  return (
    <button
      onClick={() => props.onClick(props.route)}
      className="ag-nav-btn"
      aria-current={props.active ? 'page' : undefined}
    >
      {props.label}
    </button>
  );
}

function Panel(props: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="ag-card ag-panel">
      <div className="ag-panel-head">
        <h2 className="ag-h2">{props.title}</h2>
        {props.right}
      </div>
      {props.children}
    </section>
  );
}

export function App() {
  const [route, setRoute] = useState<Route>('dashboard');
  const [oracleUrl, setOracleUrl] = useState<string>(localStorage.getItem('alpenguard.oracleUrl') ?? 'http://127.0.0.1:8787');
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);

  const header = useMemo(() => {
    const title =
      route === 'dashboard'
        ? 'Dashboard'
        : route === 'traces'
          ? 'Trace Explorer'
          : route === 'redteam'
            ? 'Red-Teaming Runs'
            : route === 'payments'
              ? 'Micropayments'
              : 'Settings';
    return title;
  }, [route]);

  return (
    <div className="ag-app">
      <div className="ag-shell">
        <aside className="ag-sidebar" style={{ display: sidebarOpen ? 'flex' : undefined }}>
          <div className="ag-card">
            <div className="ag-card-inner ag-brand">
              <div className="ag-brand-title">AlpenGuard Console</div>
              <div className="ag-brand-sub">Security, compliance, red-teaming</div>
            </div>
          </div>

          <nav className="ag-nav" aria-label="Primary navigation">
            <NavItem label="Dashboard" route="dashboard" active={route === 'dashboard'} onClick={(r) => {
              setRoute(r);
              setSidebarOpen(false);
            }} />
            <NavItem label="Trace Explorer" route="traces" active={route === 'traces'} onClick={(r) => {
              setRoute(r);
              setSidebarOpen(false);
            }} />
            <NavItem label="Red-Teaming" route="redteam" active={route === 'redteam'} onClick={(r) => {
              setRoute(r);
              setSidebarOpen(false);
            }} />
            <NavItem label="Micropayments" route="payments" active={route === 'payments'} onClick={(r) => {
              setRoute(r);
              setSidebarOpen(false);
            }} />
            <NavItem label="Settings" route="settings" active={route === 'settings'} onClick={(r) => {
              setRoute(r);
              setSidebarOpen(false);
            }} />
          </nav>

          <div className="ag-card">
            <div className="ag-card-inner">
              <div className="ag-field-label">Compliance Oracle URL</div>
              <input
                value={oracleUrl}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                  setOracleUrl(e.target.value);
                }}
                onBlur={() => {
                  localStorage.setItem('alpenguard.oracleUrl', oracleUrl);
                }}
                className="ag-input"
                placeholder="http://127.0.0.1:8787"
                spellCheck={false}
                inputMode="url"
              />
              <div className="ag-body" style={{ marginTop: 10 }}>
                Tip: start the oracle and use Trace Explorer to verify health.
              </div>
            </div>
          </div>
        </aside>

        <main className="ag-main">
          <div className="ag-topbar">
            <div>
              <h1 className="ag-h1">{header}</h1>
              <div className="ag-meta">Phase 1 operator console</div>
            </div>

            <button
              className="ag-btn ag-mobile-only"
              onClick={() => setSidebarOpen((v) => !v)}
              aria-expanded={sidebarOpen}
            >
              {sidebarOpen ? 'Close menu' : 'Menu'}
            </button>
          </div>

          {route === 'dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="ag-callout">
                <div className="ag-callout-title">What is AlpenGuard?</div>
                <div className="ag-lead">
                  AlpenGuard is a security-first middleware layer for autonomous AI agents on Solana.
                  It provides compliance enforcement, trace-mapped auditability (EU AI Act readiness),
                  adversarial red-teaming, and an execution/payment perimeter for safe agent operations.
                </div>

                <ul className="ag-ul">
                  <li><span className="ag-pill">Compliance Oracle</span> Protocol-level identity + policy checks (ACE boundary, MoltID).</li>
                  <li><span className="ag-pill">Execution Kernel</span> Multi-agent runtime aligned with Solana finality and parallelism.</li>
                  <li><span className="ag-pill">Red-Teaming Engine</span> Behavioral chaos engineering + jailbreak simulation.</li>
                  <li><span className="ag-pill">Micropayments</span> Native x402 HTTP 402, gasless USDC per-request settlement.</li>
                </ul>
              </div>

              <div className="ag-grid">
                <Panel
                  title="Getting Started (Dev)"
                  right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />checklist</span>}
                >
                  <div className="ag-body">
                    Run these in order to validate an end-to-end trace flow:
                    <ol className="ag-ul">
                      <li>Start the console (Vite) and open <strong>Trace Explorer</strong>.</li>
                      <li>Start the Compliance Oracle API.</li>
                      <li>Set <code>ALPENGUARD_KMS_KEY_B64</code> so traces can be encrypted at rest.</li>
                      <li>(Public) Enable OIDC and issue a token with <strong>traces:read</strong> and <strong>traces:ingest</strong>.</li>
                      <li>In Trace Explorer: paste token, list traces, fetch payload preview.</li>
                    </ol>
                  </div>
                </Panel>

                <Panel
                  title="Security Posture"
                  right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />in progress</span>}
                >
                  <div className="ag-body">
                    <div><strong>Authentication</strong>: OIDC JWT validation via JWKS (recommended for public).</div>
                    <div><strong>Rate limiting</strong>: enforced on API endpoints.</div>
                    <div><strong>Encryption at rest</strong>: AES-256-GCM for trace payloads (env-provided key).</div>
                    <div><strong>Trace integrity</strong>: payload SHA-256 verification on ingest.</div>
                  </div>
                </Panel>
              </div>

              <Panel title="Console Sections" right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />help</span>}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 10 }}>
                  <details className="ag-details" open>
                    <summary>Dashboard</summary>
                    <div className="ag-body" style={{ marginTop: 8 }}>
                      High-level posture summary: what is running, what is protected, and what is missing for a safe public launch.
                    </div>
                  </details>
                  <details className="ag-details">
                    <summary>Trace Explorer</summary>
                    <div className="ag-body" style={{ marginTop: 8 }}>
                      EU AI Act trace-mapping foundation. Lists encrypted traces stored by the oracle and fetches payload previews.
                      In public mode, endpoints require OIDC scopes/permissions.
                    </div>
                  </details>
                  <details className="ag-details">
                    <summary>Red-Teaming</summary>
                    <div className="ag-body" style={{ marginTop: 8 }}>
                      Runs adversarial “challenger-solver” simulations to probe failure modes (jailbreak attempts, policy bypass, rebalancing manipulation).
                    </div>
                  </details>
                  <details className="ag-details">
                    <summary>Micropayments</summary>
                    <div className="ag-body" style={{ marginTop: 8 }}>
                      x402 HTTP 402 payment perimeter: per-request settlement using gasless USDC, designed for stateless handshakes.
                    </div>
                  </details>
                  <details className="ag-details">
                    <summary>Settings</summary>
                    <div className="ag-body" style={{ marginTop: 8 }}>
                      Admin configuration surface. In release mode this will include MFA-required administration, RBAC policy, and audit export.
                    </div>
                  </details>
                </div>
              </Panel>
            </div>
          )}

          {route === 'traces' && <TraceExplorer oracleUrl={oracleUrl} />}

          {route === 'redteam' && (
            <Panel title="Red-Teaming Runs" right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />scaffold</span>}> 
              <div className="ag-body">UI scaffold. Next: run templates + results timeline.</div>
            </Panel>
          )}

          {route === 'payments' && (
            <Panel title="Micropayments" right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />scaffold</span>}> 
              <div className="ag-body">UI scaffold. Next: x402 handshake inspector + settlement status.</div>
            </Panel>
          )}

          {route === 'settings' && (
            <Panel title="Settings" right={<span className="ag-badge"><span className="ag-dot ag-dot-idle" />placeholder</span>}> 
              <div className="ag-body">Auth/MFA placeholders. Next: admin session + device binding.</div>
            </Panel>
          )}
        </main>
      </div>
    </div>
  );
}

function TraceExplorer(props: { oracleUrl: string }) {
  const [status, setStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
  const [lastHttp, setLastHttp] = useState<number | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);

  const [rememberToken, setRememberToken] = useState<boolean>(localStorage.getItem('alpenguard.rememberToken') === '1');
  const [token, setToken] = useState<string>(localStorage.getItem('alpenguard.bearer') ?? '');
  const [tenantId, setTenantId] = useState<string>(localStorage.getItem('alpenguard.tenantId') ?? '');
  const [listStatus, setListStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
  const [items, setItems] = useState<TraceSummary[]>([]);
  const [selected, setSelected] = useState<TraceSummary | null>(null);
  const [payloadB64, setPayloadB64] = useState<string>('');
  const [payloadPreview, setPayloadPreview] = useState<string>('');
  const [getStatus, setGetStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');

  const trimmedToken = token.trim();

  if (!rememberToken && token) {
    localStorage.removeItem('alpenguard.bearer');
  }

  async function ping() {
    setStatus('loading');
    try {
      const t0 = performance.now();
      const res = await fetch(`${props.oracleUrl}/healthz`);
      const t1 = performance.now();
      setLastHttp(res.status);
      setStatus(res.ok ? 'ok' : 'error');
      setLatencyMs(Math.round(t1 - t0));
    } catch {
      setLastHttp(null);
      setStatus('error');
      setLatencyMs(null);
    }
  }

  async function listTraces() {
    setListStatus('loading');
    setSelected(null);
    setPayloadB64('');
    setPayloadPreview('');
    try {
      const res = await fetch(`${props.oracleUrl}/v1/traces:list`, {
        method: 'GET',
        headers: trimmedToken ? { Authorization: `Bearer ${trimmedToken}` } : undefined,
      });

      if (!res.ok) {
        setListStatus('error');
        return;
      }

      const data = (await res.json()) as { items?: TraceSummary[] };
      setItems(Array.isArray(data.items) ? data.items : []);
      setListStatus('ok');
    } catch {
      setListStatus('error');
    }
  }

  async function getTrace(t: TraceSummary) {
    setSelected(t);
    setPayloadB64('');
    setPayloadPreview('');
    setGetStatus('loading');
    try {
      const res = await fetch(`${props.oracleUrl}/v1/traces:get`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(trimmedToken ? { Authorization: `Bearer ${trimmedToken}` } : {}),
        },
        body: JSON.stringify({ tenant_id: t.tenant_id, trace_id: t.trace_id, span_id: t.span_id }),
      });

      if (!res.ok) {
        setGetStatus('error');
        return;
      }

      const data = (await res.json()) as { payload_b64?: string };
      const b64 = typeof data.payload_b64 === 'string' ? data.payload_b64 : '';
      setPayloadB64(b64);
      setPayloadPreview(decodeB64Preview(b64));
      setGetStatus('ok');
    } catch {
      setGetStatus('error');
    }
  }

  const badge =
    status === 'ok' ? (
      <span className="ag-badge">
        <span className="ag-dot ag-dot-ok" />
        healthy
        {lastHttp !== null ? ` (HTTP ${lastHttp})` : ''}
        {latencyMs !== null ? ` · ${latencyMs}ms` : ''}
      </span>
    ) : status === 'error' ? (
      <span className="ag-badge">
        <span className="ag-dot ag-dot-error" />
        unreachable
        {lastHttp !== null ? ` (HTTP ${lastHttp})` : ''}
      </span>
    ) : status === 'loading' ? (
      <span className="ag-badge">
        <span className="ag-dot ag-dot-loading" />
        checking…
      </span>
    ) : (
      <span className="ag-badge">
        <span className="ag-dot ag-dot-idle" />
        idle
      </span>
    );

  return (
    <Panel
      title="Trace Explorer"
      right={badge}
    >
      <div className="ag-row" style={{ marginBottom: 12 }}>
        <button className="ag-btn ag-btn-primary" onClick={ping} disabled={status === 'loading'}>
          {status === 'loading' ? 'Pinging…' : 'Ping Oracle'}
        </button>
        <div className="ag-body" style={{ wordBreak: 'break-word' }}>
          Target: <span style={{ color: 'var(--text)' }}>{props.oracleUrl}</span>
        </div>
      </div>

      <div className="ag-card" style={{ borderRadius: 'var(--r16)', border: '1px solid var(--border)' }}>
        <div className="ag-card-inner">
          <div className="ag-field-label">Bearer token (OIDC access token)</div>
          <input
            className="ag-input"
            value={token}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
              setToken(e.target.value);
            }}
            onBlur={() => {
              if (rememberToken) {
                localStorage.setItem('alpenguard.bearer', token);
              }
            }}
            placeholder="Paste access token here"
            spellCheck={false}
          />

          <label className="ag-body" style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10 }}>
            <input
              type="checkbox"
              checked={rememberToken}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                const next = e.target.checked;
                setRememberToken(next);
                localStorage.setItem('alpenguard.rememberToken', next ? '1' : '0');
                if (!next) {
                  localStorage.removeItem('alpenguard.bearer');
                } else if (token) {
                  localStorage.setItem('alpenguard.bearer', token);
                }
              }}
            />
            Remember token on this device
          </label>

          <div className="ag-field-label" style={{ marginTop: 16 }}>Tenant ID (multi-tenancy)</div>
          <input
            className="ag-input"
            value={tenantId}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
              setTenantId(e.target.value);
            }}
            onBlur={() => {
              localStorage.setItem('alpenguard.tenantId', tenantId);
            }}
            placeholder="e.g., acme-corp"
            spellCheck={false}
          />
          <div className="ag-body" style={{ marginTop: 6, fontSize: 12 }}>
            Required for multi-tenant deployments. Leave empty for single-tenant dev mode.
          </div>

          <div className="ag-row" style={{ marginTop: 12 }}>
            <button className="ag-btn" onClick={listTraces} disabled={listStatus === 'loading'}>
              {listStatus === 'loading' ? 'Loading…' : 'List traces'}
            </button>
            <span className="ag-badge">
              <span className={`ag-dot ${listStatus === 'ok' ? 'ag-dot-ok' : listStatus === 'error' ? 'ag-dot-error' : listStatus === 'loading' ? 'ag-dot-loading' : 'ag-dot-idle'}`} />
              {listStatus}
              {items.length ? ` · ${items.length}` : ''}
            </span>
            <span className="ag-badge">
              <span className={`ag-dot ${getStatus === 'ok' ? 'ag-dot-ok' : getStatus === 'error' ? 'ag-dot-error' : getStatus === 'loading' ? 'ag-dot-loading' : 'ag-dot-idle'}`} />
              payload
              {getStatus !== 'idle' ? `: ${getStatus}` : ''}
            </span>
          </div>

          {items.length > 0 && (
            <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
              {items.slice(0, 50).map((t) => {
                const active = selected?.trace_id === t.trace_id && selected?.span_id === t.span_id;
                return (
                  <button
                    key={`${t.trace_id}:${t.span_id}`}
                    className="ag-nav-btn"
                    aria-current={active ? 'page' : undefined}
                    onClick={() => void getTrace(t)}
                    style={{ textAlign: 'left' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                      <div style={{ fontWeight: 700 }}>{t.event_type}</div>
                      <div style={{ fontSize: 12, color: 'var(--muted2)' }}>{new Date(t.ts_unix_ms).toLocaleString()}</div>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                      tenant: {t.tenant_id} · agent: {t.agent_id}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--muted2)', marginTop: 2 }}>
                      trace: {t.trace_id} · span: {t.span_id}
                    </div>
                  </button>
                );
              })}
            </div>
          )}

          {(payloadB64 || payloadPreview) && (
            <div style={{ marginTop: 12 }}>
              <div className="ag-field-label">Payload preview (UTF-8 best-effort)</div>
              <div
                className="ag-card"
                style={{
                  marginTop: 8,
                  borderRadius: 'var(--r16)',
                  border: '1px solid var(--border)',
                  background: 'rgba(5,10,20,.45)',
                  boxShadow: 'none',
                }}
              >
                <div className="ag-card-inner" style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace' }}>
                  <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, color: 'var(--text)' }}>
                    {payloadPreview || '[binary payload]'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="ag-body">
        This page will evolve into an EU AI Act trace-mapping explorer:
        <div>- Trace IDs anchored on-chain (hashes/events)</div>
        <div>- Off-chain spans stored encrypted</div>
        <div>- Export to audit bundles</div>
      </div>
    </Panel>
  );
}

type TraceSummary = {
  tenant_id: string;
  trace_id: string;
  span_id: string;
  ts_unix_ms: number;
  agent_id: string;
  event_type: string;
  payload_sha256_b64: string;
};

function decodeB64Preview(b64: string): string {
  try {
    if (!b64) return '';
    if (b64.length > 64_000) return '';
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const text = decoder.decode(bytes);
    const trimmed = text.length > 4000 ? `${text.slice(0, 4000)}\n…(truncated)…` : text;
    return trimmed;
  } catch {
    return '';
  }
}
