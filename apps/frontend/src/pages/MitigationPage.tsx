import { useState, useEffect } from 'react';
import type { ApiRecord } from '../hooks/useSentinelData';
import { Shield, ShieldAlert, ShieldCheck, Clock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { post, get } from '../api.mjs';

type MitigationAction = {
  id: string;
  action_type: string;
  status: string;
  submitted_at: string;
  target_flow?: string;
  ttl_seconds?: number;
  reason?: string;
};

function StatusIcon({ status }: { status: string }) {
  if (status === 'DISABLED') return <Shield size={20} className="icon-muted" />;
  if (status === 'SUBMITTED') return <Clock size={20} className="icon-amber" />;
  if (status === 'CONFIRMED') return <ShieldCheck size={20} className="icon-green" />;
  if (status === 'ROLLED_BACK') return <CheckCircle size={20} className="icon-muted" />;
  if (status === 'FAILED') return <XCircle size={20} className="icon-red" />;
  return <ShieldAlert size={20} className="icon-amber" />;
}

export function MitigationPage({
  state,
  reason,
  liveStatus,
  mitigationActions: externalActions,
  mitigationPolicy: externalPolicy,
  refresh: externalRefresh,
}: {
  state: string;
  reason: string;
  liveStatus: ApiRecord | null;
  mitigationActions?: ApiRecord[];
  mitigationPolicy?: ApiRecord | null;
  refresh?: () => void;
}) {
  const [actions, setActions] = useState<MitigationAction[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [messageType, setMessageType] = useState<'info' | 'error'>('info');
  const [policy, setPolicy] = useState<ApiRecord | null>(null);

  // Use externally-fetched data if available, otherwise self-fetch
  useEffect(() => {
    if (externalPolicy !== undefined) {
      setPolicy(externalPolicy);
    } else {
      void get('/mitigation/policy').then((p) => setPolicy(p as ApiRecord)).catch(() => {});
    }
  }, [externalPolicy]);

  useEffect(() => {
    if (externalActions !== undefined && externalActions.length > 0) {
      setActions(externalActions as MitigationAction[]);
    } else {
      void get('/mitigation/actions?limit=20&offset=0')
        .then((r) => {
          if (Array.isArray((r as ApiRecord).items)) {
            setActions((r as ApiRecord).items as MitigationAction[]);
          }
        })
        .catch(() => {});
    }
  }, [externalActions]);

  const requestMitigation = async (actionType: string, flowId?: string) => {
    setBusy(true);
    setMessage(null);
    try {
      const payload: Record<string, unknown> = {
        action_type: actionType,
        ttl_seconds: 60,
        reason: `Manual ${actionType} requested from dashboard`,
      };
      if (flowId) payload.target_flow = flowId;
      const result = await post('/mitigation/actions', payload) as ApiRecord;
      setActions(prev => [result as MitigationAction, ...prev]);
      setMessage(`Mitigation action ${actionType} submitted (ID: ${String(result.id || '—')}). Status: ${String(result.status || 'SUBMITTED')}`);
      setMessageType('info');
      if (externalRefresh) externalRefresh();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
      setMessageType('error');
    } finally {
      setBusy(false);
    }
  };

  const controllerConnected = liveStatus?.controller === 'CONNECTED';
  const scoringEnabled = liveStatus?.scoring_enabled === true;
  const hasAnomalies = actions.some(a => a.status === 'SUBMITTED' || a.status === 'CONFIRMED');

  return (
    <section>
      <div className="page-title">
        <div>
          <div className="eyebrow">SENTINEL / DEFENSE</div>
          <h1>Mitigation Lifecycle</h1>
          <p>Flow-scoped, time-limited, logged, and reversible mitigation actions.</p>
        </div>
        <span className={`status-pill ${state === 'DISABLED' ? 'muted' : ''}`}>{state}</span>
      </div>

      {/* Status overview */}
      <div className="metrics">
        <article className="metric">
          <div>
            <div className="metric-label">Controller</div>
            <div className="metric-value">{String(liveStatus?.controller || 'STALE')}</div>
            <div className="metric-detail">{String(liveStatus?.controller_reason || 'No heartbeat')}</div>
          </div>
        </article>
        <article className="metric">
          <div>
            <div className="metric-label">Scoring</div>
            <div className="metric-value">{scoringEnabled ? 'ACTIVE' : 'INACTIVE'}</div>
            <div className="metric-detail">{String(liveStatus?.live_detection || 'UNAVAILABLE')}</div>
          </div>
        </article>
        <article className="metric">
          <div>
            <div className="metric-label">Mitigation State</div>
            <div className="metric-value">{state}</div>
            <div className="metric-detail">{reason.substring(0, 60)}</div>
          </div>
        </article>
        <article className="metric">
          <div>
            <div className="metric-label">Active Actions</div>
            <div className="metric-value">{actions.filter(a => a.status === 'SUBMITTED' || a.status === 'CONFIRMED').length}</div>
            <div className="metric-detail">{actions.length} total in history</div>
          </div>
        </article>
      </div>

      {/* Policy information */}
      {policy && (
        <div className="panel">
          <div className="panel-head">
            <div>
              <h2>Active Risk Policy</h2>
              <p>Defense policy configuration for this appliance instance.</p>
            </div>
          </div>
          <div className="detail-grid">
            <div><dt>Policy ID</dt><dd>{String(policy.policy_id || 'default')}</dd></div>
            <div><dt>Max FPR</dt><dd>{String(policy.max_false_positive_rate || '0.10')}</dd></div>
            <div><dt>Min Confidence</dt><dd>{String(policy.min_confidence || '0.85')}</dd></div>
            <div><dt>Default TTL</dt><dd>{String(policy.default_ttl_seconds || 300)}s</dd></div>
            <div><dt>Rate Limiting</dt><dd>{String(policy.rate_limiting || 'UNSUPPORTED')}</dd></div>
            <div><dt>Protected Flows</dt><dd>{Array.isArray(policy.protected_flows) ? (policy.protected_flows as string[]).join(', ') || 'None defined' : 'None defined'}</dd></div>
          </div>
        </div>
      )}

      {/* Mitigation request panel */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>Request Mitigation Action</h2>
            <p>Actions are flow-scoped, time-limited, and independently verified. Rate limiting is unsupported.</p>
          </div>
        </div>
        {!controllerConnected && (
          <p className="callout warning">
            <AlertTriangle size={13} />
            Controller not connected. Mitigation actions can be staged but cannot be verified without an active OpenFlow datapath.
          </p>
        )}
        <div className="mitigation-actions-row" style={{display:'flex',gap:'10px',flexWrap:'wrap',margin:'12px 0'}}>
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => void requestMitigation('BLOCK_SOURCE_IP', '10.0.0.2')}
          >
            <Shield size={14}/> Block Source IP (demo)
          </button>
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => void requestMitigation('RATE_LIMIT_FLOW')}
          >
            <AlertTriangle size={14}/> Rate-Limit Flow (demo)
          </button>
          <button
            className="button danger"
            disabled={busy || !hasAnomalies}
            onClick={() => void requestMitigation('ROLLBACK_ALL')}
          >
            <XCircle size={14}/> Rollback All Active
          </button>
        </div>
        {message && (
          <p role="alert" className={`state ${messageType === 'error' ? 'error' : ''}`} style={{margin:'8px 0'}}>
            {message}
          </p>
        )}
      </div>

      {/* Action history */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>Action History</h2>
            <p>Submitted, confirmed, and rolled-back mitigation actions. Each action has an independent OVS verification step.</p>
          </div>
        </div>
        {actions.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Target</th>
                  <th>TTL</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((a, i) => (
                  <tr key={a.id || i}>
                    <td>{a.submitted_at || '—'}</td>
                    <td>{a.action_type || '—'}</td>
                    <td>
                      <span style={{display:'flex',alignItems:'center',gap:'5px'}}>
                        <StatusIcon status={a.status} />
                        {a.status}
                      </span>
                    </td>
                    <td><code style={{fontSize:'10px'}}>{a.target_flow || '—'}</code></td>
                    <td>{a.ttl_seconds ? `${a.ttl_seconds}s` : '—'}</td>
                    <td style={{maxWidth:'200px'}}>{a.reason || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="mitigation-empty">
            <Shield size={26} />
            <h3>No mitigation actions recorded</h3>
            <p>{reason}</p>
            <p>Submission, independent OVS confirmation, TTL expiry, and verified rollback are separate lifecycle stages.</p>
          </div>
        )}
      </div>

      <p className="callout">
        Live mitigation requires: active OpenFlow controller connection, validated detection evidence,
        risk policy approval, and a target-flow scope. Rate limiting is unsupported (no OVS meter implementation).
        All actions are bounded, reversible, and logged.
      </p>
    </section>
  );
}
