import type { ApiRecord } from '../hooks/useSentinelData';
import { AsyncState } from '../components/common/AsyncState';
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

function MetricBar({ label, value, total }: { label: string; value: number; total: number }) {
  const pct = total > 0 ? (value / total) * 100 : 0;
  return (
    <div style={{ marginBottom: '6px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#536178', marginBottom: '3px' }}>
        <span>{label}</span>
        <span style={{ fontWeight: 600 }}>{value} / {total} ({pct.toFixed(1)}%)</span>
      </div>
      <div style={{ height: '6px', background: '#edf0f3', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: '#3571b5', borderRadius: '4px' }} />
      </div>
    </div>
  );
}

function ConfusionMatrix({ matrix, labels }: { matrix: number[][]; labels: string[] }) {
  if (!matrix?.length || !labels?.length) return null;
  const total = matrix.flat().reduce((s, v) => s + v, 0);
  return (
    <div style={{ margin: '12px 0' }}>
      <div style={{ fontSize: '10px', fontWeight: 700, color: '#7a8898', marginBottom: '6px', letterSpacing: '0.4px' }}>
        CONFUSION MATRIX
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ borderCollapse: 'collapse', fontSize: '11px' }}>
          <thead>
            <tr>
              <th style={{ padding: '4px 10px', background: '#f4f6f9', border: '1px solid #e0e5eb', fontSize: '9px', color: '#7a8898' }}>
                Actual ↓ / Predicted →
              </th>
              {labels.map(l => (
                <th key={l} style={{ padding: '4px 14px', background: '#f4f6f9', border: '1px solid #e0e5eb', fontSize: '9px', color: '#7a8898' }}>
                  {l}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, ri) => (
              <tr key={ri}>
                <td style={{ padding: '6px 10px', border: '1px solid #e0e5eb', fontWeight: 600, color: '#3a4a60', fontSize: '10px', background: '#f9fafc' }}>
                  {labels[ri]}
                </td>
                {row.map((val, ci) => {
                  const isDiag = ri === ci;
                  return (
                    <td key={ci} style={{
                      padding: '6px 14px', border: '1px solid #e0e5eb',
                      textAlign: 'center', fontWeight: isDiag ? 700 : 400,
                      color: isDiag ? '#1a7a3e' : '#c04040',
                      background: isDiag ? '#edf8f1' : val > 0 ? '#fef2f2' : '#fff',
                      fontSize: '12px',
                    }}>
                      {val}
                      <div style={{ fontSize: '8px', color: '#9aa5b4', fontWeight: 400 }}>
                        {total > 0 ? `${(val / total * 100).toFixed(1)}%` : ''}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ModelCard({ model }: { model: ApiRecord }) {
  const isOffline = String(model.family || '').includes('OFFLINE');
  const isHistorical = String(model.family || '').includes('HISTORICAL');
  const isLive = String(model.model_id || '').includes('live');
  const available = model.inference_enabled === true || model.status === 'LOADABLE';

  const metrics = model.metrics as Record<string, Record<string, number | number[][]>> | undefined;
  const testMetrics = metrics?.test as Record<string, number | number[][] | Record<string, number>> | undefined;
  const valMetrics = metrics?.validation as Record<string, number | number[][] | Record<string, number>> | undefined;

  const testAcc = typeof testMetrics?.accuracy === 'number' ? testMetrics.accuracy : null;
  const testF1 = typeof testMetrics?.macro_f1 === 'number' ? testMetrics.macro_f1 : null;
  const testFpr = typeof testMetrics?.benign_fpr === 'number' ? testMetrics.benign_fpr : null;
  const testFnr = typeof testMetrics?.attack_fnr === 'number' ? testMetrics.attack_fnr : null;
  const valAcc = typeof valMetrics?.accuracy === 'number' ? valMetrics.accuracy : null;
  const valF1 = typeof valMetrics?.macro_f1 === 'number' ? valMetrics.macro_f1 : null;

  const support = testMetrics?.support as Record<string, number> | undefined;
  const confusionMatrix = testMetrics?.confusion_matrix as number[][] | undefined;
  const labelOrder = testMetrics?.label_order as string[] | undefined;

  const showMetrics = testAcc !== null || valAcc !== null;
  const showFprFnr = testFpr !== null || testFnr !== null;

  const borderColor = isHistorical ? '#e0e5eb' : available ? '#b9e0c7' : '#dde2ea';
  const headerBg = isHistorical ? '#f7f8fa' : available ? '#f0f9f4' : '#f7f8fa';

  return (
    <div style={{
      border: `1px solid ${borderColor}`, borderRadius: '8px',
      marginBottom: '14px', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ background: headerBg, padding: '14px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '9px', fontWeight: 700, color: '#7a8898', letterSpacing: '0.5px', marginBottom: '3px' }}>
            {isOffline ? 'OFFLINE CLASSIFIER' : isLive ? 'LIVE ANOMALY SCORER' : isHistorical ? 'HISTORICAL RESULT' : 'MODEL'}
          </div>
          <div style={{ fontWeight: 700, fontSize: '14px', color: '#1a2a40' }}>
            {String(model.model_id || '—')}
          </div>
          <div style={{ fontSize: '10px', color: '#7a8898', marginTop: '2px' }}>
            {String(model.task || model.family || '—')}
            {model.version ? ` · v${String(model.version)}` : ''}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '5px' }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '4px',
            background: available ? '#d1f0df' : '#f0f1f3',
            color: available ? '#1a7a3e' : '#687386',
            fontSize: '9px', fontWeight: 700, padding: '3px 8px', borderRadius: '10px',
          }}>
            {available ? <CheckCircle size={10} /> : <XCircle size={10} />}
            {String(model.status || 'UNAVAILABLE')}
          </span>
          {model.inference_enabled === true && (
            <span style={{
              fontSize: '9px', background: '#e8f4ff', color: '#2060a0',
              padding: '2px 7px', borderRadius: '8px', fontWeight: 600,
            }}>
              Inference enabled
            </span>
          )}
          {model.live_eligible === true && (
            <span style={{
              fontSize: '9px', background: '#f0e8ff', color: '#6030a0',
              padding: '2px 7px', borderRadius: '8px', fontWeight: 600,
            }}>
              Live eligible
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: '14px 16px' }}>
        {/* Feature schema */}
        <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginBottom: '10px', fontSize: '10px' }}>
          <div>
            <span style={{ color: '#8a96a8' }}>Schema: </span>
            <code style={{ color: '#3a4a60' }}>{String(model.feature_schema_id || '—')}</code>
          </div>
          {!!model.feature_count && (
            <div>
              <span style={{ color: '#8a96a8' }}>Features: </span>
              <strong style={{ color: '#3a4a60' }}>{String(model.feature_count)}</strong>
            </div>
          )}
          {!!model.artifact_sha256 && (
            <div>
              <span style={{ color: '#8a96a8' }}>SHA-256: </span>
              <code style={{ color: '#3a4a60', fontSize: '9px' }}>
                {String(model.artifact_sha256).slice(0, 16)}…
              </code>
            </div>
          )}
        </div>

        {/* Performance metrics grid */}
        {showMetrics ? (
          <div>
            <div style={{ fontSize: '10px', fontWeight: 700, color: '#7a8898', marginBottom: '8px', letterSpacing: '0.4px' }}>
              PERFORMANCE METRICS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px,1fr))', gap: '8px', marginBottom: '12px' }}>
              {[
                { label: 'Test Accuracy', value: testAcc, color: '#3571b5' },
                { label: 'Test Macro F1', value: testF1, color: '#3571b5' },
                { label: 'Val Accuracy', value: valAcc, color: '#5a8a6a' },
                { label: 'Val Macro F1', value: valF1, color: '#5a8a6a' },
              ].filter(m => m.value !== null).map(m => (
                <div key={m.label} style={{
                  background: '#f8fafc', border: '1px solid #e5eaf2',
                  borderRadius: '6px', padding: '10px', textAlign: 'center',
                }}>
                  <div style={{ fontSize: '9px', color: '#8a98a8', marginBottom: '4px' }}>{m.label}</div>
                  <div style={{ fontSize: '20px', fontWeight: 800, color: m.color, lineHeight: 1 }}>
                    {(m.value! * 100).toFixed(1)}%
                  </div>
                </div>
              ))}
            </div>

            {/* FPR/FNR */}
            {showFprFnr ? (
              <div style={{ display: 'flex', gap: '20px', fontSize: '11px', marginBottom: '10px' }}>
                {testFpr !== null ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <AlertTriangle size={11} style={{ color: '#d08a20' }} />
                    <span style={{ color: '#7a8898' }}>Benign FPR:</span>
                    <strong style={{ color: testFpr > 0.15 ? '#c04040' : '#2a7a4a' }}>
                      {(testFpr * 100).toFixed(1)}%
                    </strong>
                  </div>
                ) : null}
                {testFnr !== null ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <AlertTriangle size={11} style={{ color: '#d08a20' }} />
                    <span style={{ color: '#7a8898' }}>Attack FNR:</span>
                    <strong style={{ color: testFnr > 0.20 ? '#c04040' : '#2a7a4a' }}>
                      {(testFnr * 100).toFixed(1)}%
                    </strong>
                  </div>
                ) : null}
              </div>
            ) : null}

            {/* Support */}
            {support != null ? (
              <div style={{ marginBottom: '10px' }}>
                {Object.entries(support).map(([cls, n]) => (
                  <MetricBar key={cls} label={cls} value={n} total={Object.values(support).reduce((s, v) => s + v, 0)} />
                ))}
              </div>
            ) : null}

            {/* Confusion matrix */}
            {confusionMatrix != null && labelOrder != null ? (
              <ConfusionMatrix matrix={confusionMatrix} labels={labelOrder} />
            ) : null}
          </div>
        ) : null}

        {/* Limitations */}
        {Array.isArray(model.limitations) && model.limitations.length > 0 && (
          <details style={{ marginTop: '10px' }}>
            <summary style={{ fontSize: '10px', color: '#2867bd', cursor: 'pointer' }}>
              Known limitations ({(model.limitations as string[]).length})
            </summary>
            <ul style={{ margin: '6px 0 0', padding: '0 0 0 16px' }}>
              {(model.limitations as string[]).map((l, i) => (
                <li key={i} style={{ fontSize: '9px', color: '#7a8898', marginBottom: '3px' }}>{l}</li>
              ))}
            </ul>
          </details>
        )}

        {/* Reason / availability note */}
        {model.reason != null ? (
          <p style={{ fontSize: '10px', color: '#8a9aaa', marginTop: '8px', borderTop: '1px solid #eef0f4', paddingTop: '8px' }}>
            {String(model.reason)}
          </p>
        ) : null}
      </div>
    </div>
  );
}

export function ModelPage({
  loading, error, refresh, models,
}: { loading: boolean; error: string | null; refresh: () => void; models: ApiRecord[] }) {
  const operational = models.filter(m => m.inference_enabled === true || m.status === 'LOADABLE');
  const historical = models.filter(m => String(m.family || '').includes('HISTORICAL'));
  const preliminary = models.filter(m => String(m.status || '').includes('PRELIMINARY') || String(m.status || '').includes('UNAPPROVED'));

  return (
    <AsyncState loading={loading} error={error} onRetry={refresh}>
      <section>
        <div className="page-title">
          <div>
            <div className="eyebrow">SENTINEL / MODELS</div>
            <h1>Model Registry</h1>
            <p>
              Offline CICFlowMeter and live rule-counter models have different input schemas
              and are never interchanged. SHAP explanations are exact linear attributions.
            </p>
          </div>
        </div>

        {/* Summary */}
        <div className="metrics" style={{ gridTemplateColumns: 'repeat(3,minmax(0,1fr))', marginBottom: '20px' }}>
          <article className="metric">
            <div>
              <div className="metric-label">Operational Models</div>
              <div className="metric-value" style={{ color: '#2a7a4a' }}>{operational.length}</div>
              <div className="metric-detail">Inference-enabled</div>
            </div>
          </article>
          <article className="metric">
            <div>
              <div className="metric-label">Preliminary (Unapproved)</div>
              <div className="metric-value" style={{ color: '#d08a20' }}>{preliminary.length}</div>
              <div className="metric-detail">Research only, not deployed</div>
            </div>
          </article>
          <article className="metric">
            <div>
              <div className="metric-label">Historical Results</div>
              <div className="metric-value">{historical.length}</div>
              <div className="metric-detail">Past experiment records</div>
            </div>
          </article>
        </div>

        {/* Operational */}
        {operational.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ fontSize: '12px', fontWeight: 700, color: '#536178', letterSpacing: '0.5px', marginBottom: '12px' }}>
              OPERATIONAL MODELS
            </h2>
            {operational.map((m, i) => <ModelCard key={String(m.model_id || i)} model={m} />)}
          </div>
        )}

        {/* Preliminary */}
        {preliminary.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ fontSize: '12px', fontWeight: 700, color: '#536178', letterSpacing: '0.5px', marginBottom: '12px' }}>
              PRELIMINARY / UNAPPROVED
            </h2>
            <p className="callout warning">
              <AlertTriangle size={12} />
              {' '}These models are not approved for live inference. They are shown for research provenance only.
            </p>
            {preliminary.map((m, i) => <ModelCard key={String(m.model_id || i)} model={m} />)}
          </div>
        )}

        {/* Historical */}
        {historical.length > 0 && (
          <details style={{ marginBottom: '12px' }}>
            <summary style={{ fontSize: '11px', color: '#2867bd', cursor: 'pointer', fontWeight: 600, padding: '4px 0' }}>
              Historical research results ({historical.length})
            </summary>
            <div style={{ marginTop: '10px' }}>
              {historical.map((m, i) => <ModelCard key={String(m.model_id || i)} model={m} />)}
            </div>
          </details>
        )}

        {!models.length && (
          <div className="state">No model registry entries returned.</div>
        )}

        <p className="callout">
          The offline logistic regression model uses exact linear SHAP values — each feature's contribution
          equals its standardized coefficient × (value − mean) / scale. Live anomaly scoring uses a robust
          Z-score baseline calibrated on benign OpenFlow rule-counter windows. Neither model authorizes
          mitigation without validated detection evidence and policy approval.
        </p>
      </section>
    </AsyncState>
  );
}
