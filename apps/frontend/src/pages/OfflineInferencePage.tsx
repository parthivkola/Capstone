import { useState } from 'react';
import { get, post } from '../api.mjs';
import type { ApiRecord } from '../hooks/useSentinelData';
import { AsyncState } from '../components/common/AsyncState';
import { ShapBarChart } from '../components/ShapBarChart';

function finiteFeatures(fields: Record<string, unknown>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => {
      const numeric = typeof value === 'number' ? value : Number(value);
      if (!Number.isFinite(numeric)) {
        throw new Error(`Feature ${key} is not a finite number.`);
      }
      return [key, numeric];
    }),
  );
}

export function OfflineInferencePage({loading,error,refresh,datasets,models,schema}:{loading:boolean;error:string|null;refresh:()=>void;datasets:ApiRecord|null;models:ApiRecord[];schema:ApiRecord|null}) {
  const model = models.find(m => m.model_id === 'cse-cicflowmeter-binary-logistic');
  const files = Array.isArray(datasets?.files) ? datasets.files as ApiRecord[] : [];
  const [file, setFile] = useState('');
  const [limit, setLimit] = useState(10);
  const [mix, setMix] = useState<'balanced' | 'prefix'>('balanced');
  const [preview, setPreview] = useState<ApiRecord|null>(null);
  const [previewFile, setPreviewFile] = useState('');
  const [results, setResults] = useState<ApiRecord[]>([]);
  const [selectedResult, setSelectedResult] = useState<ApiRecord|null>(null);
  const [busy, setBusy] = useState(false);
  const [errorText, setErrorText] = useState<string|null>(null);

  const validate = async () => {
    if (!file) {
      setErrorText('Select an available prepared input file.');
      return;
    }
    setBusy(true);
    setErrorText(null);
    setResults([]);
    setSelectedResult(null);
    try {
      const next = await get(
        `/datasets/cse-cic-ids2018-stage5d/preview?file=${encodeURIComponent(file)}&limit=${limit}&mix=${mix}`,
      ) as ApiRecord;
      setPreview(next);
      setPreviewFile(file);
    } catch (reason) {
      setPreview(null);
      setPreviewFile('');
      setErrorText(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const run = async () => {
    const rows = Array.isArray(preview?.records) ? preview.records as ApiRecord[] : [];
    if (!model?.inference_enabled || !schema) {
      setErrorText(String(model?.reason || 'Compatible model or schema is unavailable.'));
      return;
    }
    if (!previewFile || previewFile !== file) {
      setErrorText('Re-run Validate and preview after changing the prepared source file.');
      return;
    }
    setBusy(true);
    setErrorText(null);
    const done: ApiRecord[] = [];
    try {
      for (const row of rows.slice(0, limit)) {
        const fields = (row.features || {}) as Record<string, unknown>;
        try {
          const numeric = finiteFeatures(fields);
          done.push(await post('/inference/predict', {
            model_id: model.model_id,
            feature_schema: schema.feature_schema_id,
            feature_order: schema.feature_order,
            features: numeric,
            source: {
              source_type: 'LABELED_DATA',
              dataset_id: 'cse-cic-ids2018-stage5d',
              file_id: previewFile,
              row_number: row.row_number,
            },
          }) as ApiRecord);
        } catch (reason) {
          done.push({
            row_number: row.row_number,
            error: reason instanceof Error ? reason.message : String(reason),
          });
        }
      }
      setResults(done);
      setSelectedResult(done.find(item => !item.error) || null);
      await refresh();
    } catch (reason) {
      setErrorText(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AsyncState loading={loading} error={error} onRetry={refresh}>
      <section className="panel">
        <h1>Run offline inference</h1>
        <p>Runs the registered 77-feature model on actual prepared rows. This is not live network detection.</p>
        {model?.inference_enabled ? (
          <>
            <p>
              {String(model.model_id)} v{String(model.version)} · schema {String(model.feature_schema_id)} · {String(model.artifact_sha256)}
            </p>
            <div className="form-row">
              <label htmlFor="source-file">Prepared CSE-CIC-IDS2018 source</label>
              <select
                id="source-file"
                value={file}
                onChange={event => {
                  setFile(event.target.value);
                  setPreview(null);
                  setPreviewFile('');
                  setResults([]);
                  setSelectedResult(null);
                }}
              >
                <option value="">Select file</option>
                {files.filter(item => item.available).map((item, index) => (
                  <option key={String(item.file_id || index)} value={String(item.file_id)}>
                    {String(item.file_id)}
                  </option>
                ))}
              </select>
              <label htmlFor="row-limit">Rows (1–20)</label>
              <input
                id="row-limit"
                type="number"
                min="1"
                max="20"
                value={limit}
                onChange={event => setLimit(Math.max(1, Math.min(20, Number(event.target.value) || 1)))}
              />
              <label htmlFor="mix-mode">Row mix</label>
              <select
                id="mix-mode"
                value={mix}
                onChange={event => {
                  setMix(event.target.value === 'prefix' ? 'prefix' : 'balanced');
                  setPreview(null);
                  setPreviewFile('');
                  setResults([]);
                  setSelectedResult(null);
                }}
              >
                <option value="balanced">Balanced Benign + attack</option>
                <option value="prefix">File prefix only</option>
              </select>
              <button className="button secondary" disabled={busy || !file} onClick={() => void validate()}>
                {busy ? 'Working…' : 'Validate and preview'}
              </button>
            </div>
            {preview && (
              <>
                <p className="callout">{String(preview.sampling_policy)}</p>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Row</th>
                        <th>Ground truth</th>
                        <th>Feature count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(preview.records as ApiRecord[]).map((row, index) => (
                        <tr key={String(row.row_number || index)}>
                          <td>{String(row.row_number)}</td>
                          <td>{String(row.source_label || '—')}</td>
                          <td>{String(Object.keys((row.features || {}) as object).length)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <button className="button primary" disabled={busy} onClick={() => void run()}>
                  {busy ? 'Running…' : 'Run inference'}
                </button>
              </>
            )}
            {results.length > 0 && (
              <>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Row</th>
                        <th>Prediction</th>
                        <th>Raw score</th>
                        <th>Outcome</th>
                        <th>Explain</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((row, index) => {
                        const rowNumber = String(
                          (row.provenance as ApiRecord | undefined)?.source_row_number
                          || row.row_number
                          || '—',
                        );
                        return (
                          <tr key={String(row.id || index)}>
                            <td>{rowNumber}</td>
                            <td>{String(row.predicted_label || '—')}</td>
                            <td>{String(row.confidence ?? 'Unavailable')}</td>
                            <td>{row.error ? String(row.error) : 'Persisted'}</td>
                            <td>
                              {row.error ? '—' : (
                                <button
                                  className="button secondary compact"
                                  onClick={() => setSelectedResult(row)}
                                >
                                  SHAP chart
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {selectedResult && !selectedResult.error && (
                  <ShapBarChart
                    title={`SHAP for row ${String((selectedResult.provenance as ApiRecord | undefined)?.source_row_number || selectedResult.row_number || '')} · predicted ${String(selectedResult.predicted_label)}`}
                    features={Array.isArray((selectedResult.explanation as ApiRecord | undefined)?.top_features)
                      ? ((selectedResult.explanation as ApiRecord).top_features as ApiRecord[])
                      : []}
                  />
                )}
              </>
            )}
          </>
        ) : (
          <div className="state">
            Offline inference unavailable: {String(model?.reason || 'No loadable registered model.')}
          </div>
        )}
        {errorText && <p role="alert" className="state error">{errorText}</p>}
        <p className="footnote">
          Balanced mix uses the first Benign and first attack rows in file order so inference is not stuck on a Benign-only prefix.
          Scores are uncalibrated. Exact linear SHAP explains the offline logistic decision only. Live Ryu status is separate and stays STALE until an isolated controller run publishes a heartbeat.
        </p>
      </section>
    </AsyncState>
  );
}
