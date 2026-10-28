import { useCallback, useEffect, useRef, useState } from 'react';
import { get } from '../api.mjs';

export type ApiRecord = Record<string, unknown>;
export type SentinelData = {
  status: ApiRecord | null; liveStatus: ApiRecord | null; detections: ApiRecord[]; liveScores: ApiRecord[];
  sessions: ApiRecord[]; experiments: ApiRecord[]; datasets: ApiRecord | null; telemetry: ApiRecord[];
  models: ApiRecord[]; audit: ApiRecord[]; liveLedger: ApiRecord[]; schema: ApiRecord | null;
  mitigationActions: ApiRecord[]; mitigationPolicy: ApiRecord | null;
};
const empty: SentinelData = { status: null, liveStatus: null, detections: [], liveScores: [], sessions: [], experiments: [], datasets: null, telemetry: [], models: [], audit: [], liveLedger: [], schema: null, mitigationActions: [], mitigationPolicy: null };
const records = (value: ApiRecord): ApiRecord[] => Array.isArray(value.items) ? value.items as ApiRecord[] : [];

async function allPages(path: string): Promise<ApiRecord[]> {
  const first = await get(`${path}?limit=200&offset=0`) as ApiRecord;
  const rows = records(first);
  const page = first.page as ApiRecord | undefined;
  const total = typeof page?.total === 'number' ? page.total : rows.length;
  if (total > 10000) throw new Error(`${path} exceeds the 10,000-record browser safety limit.`);
  for (let offset = rows.length; offset < total; offset += 200) rows.push(...records(await get(`${path}?limit=200&offset=${offset}`) as ApiRecord));
  return rows;
}

export function useSentinelData(pollIntervalMs = 5000) {
  const [data, setData] = useState<SentinelData>(empty);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const generation = useRef(0);
  const hasLoaded = useRef(false);
  const mounted = useRef(false);
  const fetchData = useCallback(async (manual: boolean) => {
    if (inFlight.current && !manual) return;
    inFlight.current = true;
    const requestGeneration = ++generation.current;
    if (mounted.current && !hasLoaded.current) setLoading(true);
    if (mounted.current) setError(null);
    try {
      const [status, liveStatus, detections, liveDetectionResponse, sessions, experiments, datasetResponse, telemetry, modelResponse, audit, ledgerResponse, schemaResponse, mitigActionsResponse, mitigPolicyResponse] = await Promise.all([
        get('/status'), get('/live/status'), allPages('/detections'), get('/live/detections?limit=100&offset=0'), allPages('/sessions'), allPages('/experiments'), get('/datasets'), allPages('/telemetry/audits'), get('/models'), allPages('/audit'), get('/live/ledger?limit=100&offset=0'), get('/inference/schema'),
        get('/mitigation/actions?limit=50&offset=0'), get('/mitigation/policy'),
      ]) as [ApiRecord, ApiRecord, ApiRecord[], ApiRecord, ApiRecord[], ApiRecord[], ApiRecord, ApiRecord[], ApiRecord, ApiRecord[], ApiRecord, ApiRecord, ApiRecord, ApiRecord];
      if (requestGeneration !== generation.current) return;
      const ledger = records(ledgerResponse);
      const ledgerAudit = ledger.map(row => ({ id: row.event_id, created_at: row.created_at, event_type: row.event_type, source_type: 'LIVE', outcome: row.event_type, payload: { window_id: row.window_id, ...(row.payload as object || {}) } }));
      if (!mounted.current) return;
      setData({ status, liveStatus, detections, liveScores: records(liveDetectionResponse), sessions, experiments, datasets: (datasetResponse.prepared_dataset as ApiRecord | undefined) ?? null, telemetry, models: Array.isArray(modelResponse.models) ? modelResponse.models as ApiRecord[] : [], audit: [...audit, ...ledgerAudit].sort((a,b) => String(b.created_at).localeCompare(String(a.created_at))), liveLedger: ledger, schema: Array.isArray(schemaResponse.models) ? (schemaResponse.models as ApiRecord[])[0] ?? null : null, mitigationActions: records(mitigActionsResponse), mitigationPolicy: (mitigPolicyResponse as ApiRecord) ?? null });
      hasLoaded.current = true;
    } catch (reason) {
      if (mounted.current && requestGeneration === generation.current) setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (mounted.current && requestGeneration === generation.current) setLoading(false);
      if (requestGeneration === generation.current) inFlight.current = false;
    }
  }, []);
  const refresh = useCallback(() => fetchData(true), [fetchData]);
  useEffect(() => {
    mounted.current = true;
    void fetchData(false);
    const timer = window.setInterval(() => { void fetchData(false); }, pollIntervalMs);
    return () => { mounted.current = false; generation.current++; inFlight.current = false; window.clearInterval(timer); };
  }, [fetchData, pollIntervalMs]);
  return { ...data, loading, error, refresh };
}
