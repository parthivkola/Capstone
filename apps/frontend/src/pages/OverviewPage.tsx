import { Activity, Network, ShieldAlert, Shield, CheckCircle, AlertTriangle, Zap, Database } from 'lucide-react';
import type { ApiRecord } from '../hooks/useSentinelData';
import type { PageName } from '../components/layout/AppShell';
import { AsyncState } from '../components/common/AsyncState';

const text = (v: unknown, fallback = 'Unavailable') =>
  typeof v === 'string' && v ? v : fallback;

function MetricCard({
  label, value, detail, status = 'default',
}: { label: string; value: string; detail: string; status?: 'ok' | 'warn' | 'error' | 'default' }) {
  const colors = {
    ok: { bg: '#edf7ef', icon: '#3a9e5f', dot: '#3a9e5f' },
    warn: { bg: '#fff8ed', icon: '#d08a20', dot: '#d08a20' },
    error: { bg: '#fff0ef', icon: '#bb5c56', dot: '#bb5c56' },
    default: { bg: '#edf4ff', icon: '#3771bd', dot: '#9baec8' },
  }[status];

  return (
    <article className="metric">
      <div className="metric-icon" style={{ background: colors.bg, color: colors.icon }}>
        <span style={{
          width: 8, height: 8, borderRadius: '50%',
          background: colors.dot, display: 'inline-block',
        }} />
      </div>
      <div style={{ flex: 1 }}>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        <div className="metric-detail">{detail}</div>
      </div>
    </article>
  );
}

function controllerStatus(liveStatus: ApiRecord | null, loading: boolean) {
  const c = liveStatus?.controller;
  if (loading) return { value: 'Checking…', status: 'default' as const };
  if (c === 'CONNECTED') return { value: 'CONNECTED', status: 'ok' as const };
  if (c === 'STALE') return { value: 'STALE', status: 'warn' as const };
  if (c === 'DISCONNECTED') return { value: 'DISCONNECTED', status: 'error' as const };
  return { value: String(c || 'Unknown'), status: 'default' as const };
}

function AlertBadge({ count, label }: { count: number; label: string }) {
  if (count === 0) return null;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      background: '#fff0ef', color: '#b84848',
      border: '1px solid #eec9c8', borderRadius: '20px',
      padding: '4px 10px', fontSize: '10px', fontWeight: 700,
    }}>
      <ShieldAlert size={11} /> {count} {label}
    </span>
  );
}

export function OverviewPage({
  loading, error, refresh, liveStatus, models, detections, onNavigate,
}: {
  loading: boolean; error: string | null; refresh: () => void;
  liveStatus: ApiRecord | null;
  models: ApiRecord[]; detections: ApiRecord[];
  onNavigate: (page: PageName) => void;
}) {
  const ctrl = controllerStatus(liveStatus, loading);
  const liveModel = models.find(x => String(x.model_id || '').includes('stage7-live-robust'));
  const offlineModel = models.find(x => String(x.model_id || '').includes('cse-cicflowmeter'));
  const anomalyScores = detections.filter(d => d.source_type === 'LIVE' || d.result === 'UNUSUAL');
  const offlinePredictions = detections.filter(d => d.source_type !== 'LIVE' && d.predicted_label);
  const intrusionDetections = offlinePredictions.filter(d => d.predicted_label === 'INTRUSION');

  const telemetryStatus = String(liveStatus?.telemetry || 'UNKNOWN');
  const scoringEnabled = liveStatus?.scoring_enabled === true;

  return (
    <AsyncState loading={loading} error={error} onRetry={refresh}>
      <div>
        <div className="page-title">
          <div>
            <div className="eyebrow">SENTINEL / OPERATIONS</div>
            <h1>Overview</h1>
            <p>Explainable SDN-based Network Defence Appliance — operational status.</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {intrusionDetections.length > 0 && (
              <AlertBadge count={intrusionDetections.length} label="INTRUSION predictions" />
            )}
            {anomalyScores.length > 0 && (
              <AlertBadge count={anomalyScores.length} label="anomaly events" />
            )}
          </div>
        </div>

        {/* Primary status grid */}
        <div className="metrics">
          <MetricCard
            label="SDN Controller"
            value={ctrl.value}
            detail={text(liveStatus?.controller_reason, 'No controller heartbeat reported.')}
            status={ctrl.status}
          />
          <MetricCard
            label="Telemetry"
            value={telemetryStatus}
            detail={`${String(liveStatus?.eligible_windows_this_poll ?? '—')} eligible windows · ${String(liveStatus?.accepted_windows_total ?? 0)} total`}
            status={telemetryStatus === 'FRESH_WINDOWS' ? 'ok' : 'warn'}
          />
          <MetricCard
            label="Anomaly Detector"
            value={text(liveStatus?.model_status, 'UNAVAILABLE')}
            detail={scoringEnabled ? 'Provisional scoring active' : text(liveStatus?.reason, 'Awaiting controller')}
            status={scoringEnabled ? 'ok' : 'default'}
          />
          <MetricCard
            label="Detection Readiness"
            value={text(liveStatus?.live_detection, 'UNAVAILABLE')}
            detail={text(liveStatus?.reason, 'Waiting for validated telemetry.')}
            status={liveStatus?.live_detection === 'PROVISIONAL_ANOMALY_SCORING' ? 'ok' : 'default'}
          />
        </div>

        {/* Architecture explainer */}
        <div className="grid-two">
          {/* Left: Detection pipeline */}
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Detection Pipeline</h2>
                <p>Two independent models — offline and live — with separate schemas.</p>
              </div>
            </div>
            {offlineModel && (
              <div style={{
                background: offlineModel.inference_enabled ? '#f0f9f4' : '#f7f8fa',
                border: '1px solid', borderColor: offlineModel.inference_enabled ? '#b9e0c7' : '#e0e5eb',
                borderRadius: '7px', padding: '12px', marginBottom: '10px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '10px', fontWeight: 700, color: '#7a8a9a', letterSpacing: '0.5px' }}>
                      OFFLINE CLASSIFIER
                    </div>
                    <div style={{ fontWeight: 700, color: '#243149', fontSize: '13px', marginTop: '3px' }}>
                      {String(offlineModel.model_id || '—')}
                    </div>
                    <div style={{ fontSize: '10px', color: '#7a8a9a', marginTop: '3px' }}>
                      v{String(offlineModel.version || '—')} · 77 CICFlowMeter features
                    </div>
                  </div>
                  <span style={{
                    background: offlineModel.inference_enabled ? '#d1f0df' : '#eee',
                    color: offlineModel.inference_enabled ? '#2a7a4a' : '#666',
                    fontSize: '9px', fontWeight: 700, padding: '3px 8px', borderRadius: '10px',
                  }}>
                    {Boolean(offlineModel.inference_enabled) ? '✓ READY' : 'UNAVAILABLE'}
                  </span>
                </div>
                {!!offlineModel.metrics && (
                  <div style={{ marginTop: '8px', display: 'flex', gap: '16px', fontSize: '10px' }}>
                    {(() => {
                      const m = offlineModel.metrics as Record<string, Record<string, number>>;
                      const testAcc = m?.test?.accuracy;
                      const testF1 = m?.test?.macro_f1;
                      const valAcc = m?.validation?.accuracy;
                      return (
                        <>
                          <div>
                            <span style={{ color: '#8a96a8' }}>Test Acc: </span>
                            <strong style={{ color: '#243149' }}>
                              {testAcc ? `${(testAcc * 100).toFixed(1)}%` : '—'}
                            </strong>
                          </div>
                          <div>
                            <span style={{ color: '#8a96a8' }}>Test F1: </span>
                            <strong style={{ color: '#243149' }}>
                              {testF1 ? `${(testF1 * 100).toFixed(1)}%` : '—'}
                            </strong>
                          </div>
                          <div>
                            <span style={{ color: '#8a96a8' }}>Val Acc: </span>
                            <strong style={{ color: '#243149' }}>
                              {valAcc ? `${(valAcc * 100).toFixed(1)}%` : '—'}
                            </strong>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                )}
                <button
                  className="button secondary compact"
                  style={{ marginTop: '10px' }}
                  onClick={() => onNavigate('Run Offline Inference')}
                >
                  <Zap size={12} /> Run Inference + SHAP
                </button>
              </div>
            )}
            {liveModel && (
              <div style={{
                background: '#f5f0fb', border: '1px solid #d5c8f0', borderRadius: '7px', padding: '12px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '10px', fontWeight: 700, color: '#7a8a9a', letterSpacing: '0.5px' }}>
                      LIVE ANOMALY SCORER
                    </div>
                    <div style={{ fontWeight: 700, color: '#243149', fontSize: '13px', marginTop: '3px' }}>
                      {String(liveModel.model_id || '—')}
                    </div>
                    <div style={{ fontSize: '10px', color: '#7a8a9a', marginTop: '3px' }}>
                      4 OpenFlow rule-counter features · provisional baseline
                    </div>
                  </div>
                  <span style={{
                    background: liveModel.status === 'LOADABLE' ? '#e8d9f8' : '#eee',
                    color: liveModel.status === 'LOADABLE' ? '#6a3ea0' : '#666',
                    fontSize: '9px', fontWeight: 700, padding: '3px 8px', borderRadius: '10px',
                  }}>
                    {String(liveModel.status || 'UNAVAILABLE')}
                  </span>
                </div>
              </div>
            )}
          </section>

          {/* Right: Recent threats */}
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Recent Detections</h2>
                <p>Latest offline predictions and live anomaly scores.</p>
              </div>
              <button className="text-button" onClick={() => onNavigate('Predictions')}>
                View all
              </button>
            </div>
            {offlinePredictions.length === 0 && anomalyScores.length === 0 ? (
              <div className="inline-empty">
                <Shield size={18} style={{ color: '#b0b9c5' }} />
                No detection records yet. Run offline inference or start a session.
              </div>
            ) : (
              <div>
                {[...anomalyScores, ...offlinePredictions].slice(0, 6).map((d, i) => {
                  const isIntrusion = d.predicted_label === 'INTRUSION' || d.result === 'UNUSUAL';
                  return (
                    <div key={String(d.id || d.window_id || i)} style={{
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      padding: '8px 4px',
                      borderBottom: i < 5 ? '1px solid #f0f2f5' : 'none',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {isIntrusion
                          ? <ShieldAlert size={14} style={{ color: '#c14545', flexShrink: 0 }} />
                          : <CheckCircle size={14} style={{ color: '#3a9e5f', flexShrink: 0 }} />
                        }
                        <div>
                          <div style={{ fontSize: '10px', fontWeight: 600, color: '#243149' }}>
                            {String(d.predicted_label || d.result || 'SCORED')}
                          </div>
                          <div style={{ fontSize: '9px', color: '#8a96a8' }}>
                            {String(d.model_id || d.source_type || '—')} ·{' '}
                            {String(d.prediction_timestamp || d.created_at || d.end_at || '—').slice(0, 19)}
                          </div>
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{
                          fontSize: '11px', fontWeight: 700,
                          color: isIntrusion ? '#c14545' : '#3a9e5f',
                        }}>
                          {d.confidence !== undefined
                            ? `${(Number(d.confidence) * 100).toFixed(1)}%`
                            : d.score !== undefined ? `${Number(d.score).toFixed(2)}σ` : '—'}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>

        {/* Quick actions */}
        <section className="panel">
          <div className="panel-head">
            <div><h2>Quick Actions</h2></div>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button className="button primary" onClick={() => onNavigate('Run Offline Inference')}>
              <Zap size={14} /> Run Inference + SHAP
            </button>
            <button className="button secondary" onClick={() => onNavigate('Live monitoring')}>
              <Activity size={14} /> Live Monitoring
            </button>
            <button className="button secondary" onClick={() => onNavigate('Telemetry')}>
              <Network size={14} /> Telemetry Audit
            </button>
            <button className="button secondary" onClick={() => onNavigate('Mitigation')}>
              <Shield size={14} /> Mitigation Lifecycle
            </button>
            <button className="button secondary" onClick={() => onNavigate('Project data')}>
              <Database size={14} /> Project Data
            </button>
          </div>
        </section>

        {/* Architecture note */}
        <p className="callout">
          <strong>Architecture:</strong> Offline CICFlowMeter classifier (77 features, SHAP-explainable) runs on labeled
          dataset records. Live anomaly scorer uses 4 OpenFlow rule-counter delta features from the SDN controller.
          Schemas are separate and never interchanged. Live mitigation requires an active OpenFlow controller connection.
        </p>
        {liveStatus?.controller !== 'CONNECTED' && (
          <p className="callout warning">
            <AlertTriangle size={13} />
            {' '}Controller {String(liveStatus?.controller || 'STALE')}: the simulator publishes a heartbeat every 3 s.
            If this shows STALE, the controller status file may have expired. Live scoring needs a fresh heartbeat.
          </p>
        )}
      </div>
    </AsyncState>
  );
}
