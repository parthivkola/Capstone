import { useMemo, useState } from 'react';
import type { ApiRecord } from '../hooks/useSentinelData';
import { AsyncState } from '../components/common/AsyncState';
import { ShapBarChart, ShapSummary } from '../components/ShapBarChart';
import { ShieldAlert, CheckCircle, Activity } from 'lucide-react';

function labelColor(label: string) {
  if (label === 'INTRUSION') return { color: '#b84848', background: '#fdecea', border: '1px solid #f0c8c4' };
  if (label === 'BENIGN') return { color: '#2a7a4a', background: '#edf8f1', border: '1px solid #b9e0c7' };
  if (label === 'UNUSUAL') return { color: '#a06020', background: '#fff5e0', border: '1px solid #f0dcb0' };
  return { color: '#4a5568', background: '#f0f2f4', border: '1px solid #dde2ea' };
}

export function DetectionsPage({
  loading, error, refresh, rows,
}: { loading: boolean; error: string | null; refresh: () => void; rows: ApiRecord[] }) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [filterLabel, setFilterLabel] = useState('ALL');
  const [selectedRow, setSelectedRow] = useState<ApiRecord | null>(null);

  const filtered = useMemo(() => {
    let result = rows;
    if (filterLabel !== 'ALL') {
      result = result.filter(r =>
        String(r.predicted_label || r.result || '').toUpperCase() === filterLabel
      );
    }
    if (query) {
      const q = query.toLowerCase();
      result = result.filter(r => JSON.stringify(r).toLowerCase().includes(q));
    }
    return result;
  }, [rows, query, filterLabel]);

  const shown = filtered.slice(page * 10, page * 10 + 10);
  const intrusionCount = rows.filter(r => r.predicted_label === 'INTRUSION' || r.result === 'UNUSUAL').length;
  const benignCount = rows.filter(r => r.predicted_label === 'BENIGN').length;
  const liveCount = rows.filter(r => r.source_type === 'LIVE' || r.rule_identity_id).length;

  const getShapFeatures = (row: ApiRecord): ApiRecord[] => {
    const exp = row.explanation as ApiRecord | undefined;
    if (exp && Array.isArray(exp.top_features)) return exp.top_features as ApiRecord[];
    return [];
  };

  return (
    <AsyncState loading={loading} error={error} onRetry={refresh}>
      <section>
        <div className="page-title">
          <div>
            <div className="eyebrow">SENTINEL / DETECTIONS</div>
            <h1>Detections &amp; Predictions</h1>
            <p>Offline model predictions and live anomaly scores. Scores are not calibrated probabilities.</p>
          </div>
        </div>

        {/* Summary stats */}
        <div className="metrics" style={{ gridTemplateColumns: 'repeat(4,minmax(0,1fr))' }}>
          <article className="metric">
            <div>
              <div className="metric-label">Total Records</div>
              <div className="metric-value">{rows.length}</div>
              <div className="metric-detail">All evidence types</div>
            </div>
          </article>
          <article className="metric">
            <div>
              <div className="metric-label" style={{ color: '#b84848' }}>INTRUSION / Anomalies</div>
              <div className="metric-value" style={{ color: '#b84848' }}>{intrusionCount}</div>
              <div className="metric-detail">Flagged detections</div>
            </div>
          </article>
          <article className="metric">
            <div>
              <div className="metric-label" style={{ color: '#2a7a4a' }}>BENIGN</div>
              <div className="metric-value" style={{ color: '#2a7a4a' }}>{benignCount}</div>
              <div className="metric-detail">Benign classifications</div>
            </div>
          </article>
          <article className="metric">
            <div>
              <div className="metric-label">Live Scores</div>
              <div className="metric-value">{liveCount}</div>
              <div className="metric-detail">OpenFlow anomaly windows</div>
            </div>
          </article>
        </div>

        <div className="panel">
          {/* Filters */}
          <div className="filters">
            <label className="table-search">
              Search
              <input
                aria-label="Search detections"
                value={query}
                onChange={e => { setQuery(e.target.value); setPage(0); }}
                placeholder="model, label, timestamp…"
              />
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#637087' }}>
              Filter:
              <select
                value={filterLabel}
                onChange={e => { setFilterLabel(e.target.value); setPage(0); }}
                style={{ padding: '5px 8px', border: '1px solid #dce2e9', borderRadius: '5px', fontSize: '11px' }}
              >
                <option value="ALL">All labels</option>
                <option value="INTRUSION">INTRUSION only</option>
                <option value="BENIGN">BENIGN only</option>
                <option value="UNUSUAL">UNUSUAL only</option>
              </select>
            </label>
            <span style={{ marginLeft: 'auto', fontSize: '10px', color: '#8a96a8' }}>
              {filtered.length} of {rows.length} records
            </span>
          </div>

          {shown.length ? (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Label / Result</th>
                      <th>Confidence / Score</th>
                      <th>Ground Truth</th>
                      <th>Model</th>
                      <th>Source</th>
                      <th>Top SHAP Features</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((r, i) => {
                      const label = String(r.predicted_label || r.result || '—');
                      const lc = labelColor(label);
                      const shapFeatures = getShapFeatures(r);
                      return (
                        <tr key={String(r.id || r.window_id || i)}>
                          <td style={{ whiteSpace: 'nowrap' }}>
                            {String(r.prediction_timestamp || r.created_at || r.end_at || '—').slice(0, 19)}
                          </td>
                          <td>
                            <span style={{
                              ...lc,
                              display: 'inline-block', borderRadius: '4px',
                              padding: '3px 7px', fontSize: '10px', fontWeight: 700,
                            }}>
                              {label === 'INTRUSION' && <ShieldAlert size={10} style={{ marginRight: 3 }} />}
                              {label === 'BENIGN' && <CheckCircle size={10} style={{ marginRight: 3 }} />}
                              {label === 'UNUSUAL' && <Activity size={10} style={{ marginRight: 3 }} />}
                              {label}
                            </span>
                          </td>
                          <td style={{ fontWeight: 600, color: '#243149' }}>
                            {r.confidence !== undefined
                              ? `${(Number(r.confidence) * 100).toFixed(1)}%`
                              : r.score !== undefined
                              ? `${Number(r.score).toFixed(3)}σ`
                              : '—'}
                          </td>
                          <td style={{ color: '#768397' }}>
                            {String(r.ground_truth_label || (r.provenance as ApiRecord | undefined)?.ground_truth_label || '—')}
                          </td>
                          <td style={{ fontSize: '9px', color: '#8a96a8' }}>
                            {String(r.model_id || '—')}
                            {r.model_version ? ` v${String(r.model_version)}` : ''}
                          </td>
                          <td>
                            <span className={`source-chip ${
                              r.source_type === 'LIVE' || r.rule_identity_id ? 'telemetry' :
                              r.source_type === 'REAL_DATASET_RECORD' ? 'labeled' : ''
                            }`}>
                              {String(r.source_type || 'OFFLINE').replace('_', ' ')}
                            </span>
                          </td>
                          <td>
                            {shapFeatures.length > 0
                              ? <ShapSummary features={shapFeatures} />
                              : <span style={{ color: '#aab5c0', fontSize: '9px' }}>—</span>
                            }
                          </td>
                          <td>
                            <button
                              className="button secondary compact"
                              onClick={() => setSelectedRow(selectedRow?.id === r.id ? null : r)}
                            >
                              {selectedRow?.id === r.id ? 'Hide' : 'Details'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Expanded SHAP detail panel */}
              {selectedRow && (
                <div style={{
                  margin: '12px 0', padding: '16px',
                  background: '#f8fafc', border: '1px solid #dde5ef', borderRadius: '8px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <h3 style={{ margin: 0, fontSize: '13px', color: '#243149' }}>
                      Prediction Detail — {String(selectedRow.id || selectedRow.window_id || '—').slice(0, 16)}…
                    </h3>
                    <button className="text-button" onClick={() => setSelectedRow(null)}>✕ Close</button>
                  </div>

                  <div className="detail-grid">
                    <div><dt>Predicted Label</dt><dd style={{ fontWeight: 700 }}>{String(selectedRow.predicted_label || selectedRow.result || '—')}</dd></div>
                    <div><dt>Confidence</dt><dd>{selectedRow.confidence !== undefined ? `${(Number(selectedRow.confidence) * 100).toFixed(2)}%` : '—'}</dd></div>
                    <div><dt>Model</dt><dd>{String(selectedRow.model_id || '—')} v{String(selectedRow.model_version || selectedRow.version || '—')}</dd></div>
                    <div><dt>Feature Schema</dt><dd>{String(selectedRow.feature_schema_id || '—')}</dd></div>
                    <div><dt>Ground Truth</dt><dd>{String(selectedRow.ground_truth_label || (selectedRow.provenance as ApiRecord | undefined)?.ground_truth_label || 'Not supplied')}</dd></div>
                    <div><dt>Timestamp</dt><dd>{String(selectedRow.prediction_timestamp || selectedRow.created_at || '—')}</dd></div>
                  </div>

                  {(() => {
                    const exp = selectedRow.explanation as ApiRecord | undefined;
                    const features = Array.isArray(exp?.top_features) ? exp.top_features as ApiRecord[] : [];
                    const shapTitle = `SHAP waterfall — predicted ${String(selectedRow.predicted_label || 'UNKNOWN')} with ${selectedRow.confidence !== undefined ? `${(Number(selectedRow.confidence) * 100).toFixed(1)}% confidence` : 'unknown confidence'}`;
                    return features.length > 0 ? (
                      <ShapBarChart features={features} title={shapTitle} maxFeatures={15} />
                    ) : (
                      <p className="footnote">No SHAP explanation available for this record.</p>
                    );
                  })()}

                  {/* Probabilities */}
                  {!!selectedRow.probabilities && (
                    <div style={{ marginTop: '12px' }}>
                      <h4 style={{ fontSize: '11px', margin: '0 0 6px', color: '#536178' }}>Class Probabilities</h4>
                      {Object.entries(selectedRow.probabilities as Record<string, number>).map(([cls, prob]) => (
                        <div key={cls} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <span style={{ width: '80px', fontSize: '10px', color: '#536178' }}>{cls}</span>
                          <div style={{
                            flex: 1, height: '8px', background: '#e8eef5', borderRadius: '4px', overflow: 'hidden',
                          }}>
                            <div style={{
                              width: `${prob * 100}%`, height: '100%',
                              background: cls === 'INTRUSION' ? '#d05046' : '#3571b5',
                              borderRadius: '4px',
                            }} />
                          </div>
                          <span style={{ width: '40px', fontSize: '10px', textAlign: 'right', color: '#243149', fontWeight: 600 }}>
                            {(prob * 100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {filtered.length > 10 && (
                <div className="pagination">
                  <span>{page * 10 + 1}–{Math.min((page + 1) * 10, filtered.length)} of {filtered.length}</span>
                  <button className="button secondary compact" disabled={!page} onClick={() => setPage(page - 1)}>
                    ← Previous
                  </button>
                  <button
                    className="button secondary compact"
                    disabled={(page + 1) * 10 >= filtered.length}
                    onClick={() => setPage(page + 1)}
                  >
                    Next →
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="state">
              {rows.length
                ? 'No detections match your current filter or search.'
                : 'No prediction records available. Run offline inference or start a demo session.'}
            </div>
          )}
        </div>

        <p className="callout">
          SHAP values are exact linear attributions for the logistic regression model. They represent
          standardized log-odds contributions. Live anomaly scores are not attack classifications —
          they compare current OpenFlow rule-counter deltas against a benign baseline.
        </p>
      </section>
    </AsyncState>
  );
}
