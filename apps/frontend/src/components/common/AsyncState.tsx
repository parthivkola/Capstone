import type { ReactNode } from 'react';
import { AlertTriangle, CircleHelp } from 'lucide-react';
import { API_BASE } from '../../api.mjs';

export function AsyncState({ loading, error, empty, emptyText = 'No records are available from this source.', onRetry, children }: {
  loading: boolean; error: string | null; empty?: boolean; emptyText?: string; onRetry?: () => void; children: ReactNode;
}) {
  if (loading) return <div className="state" role="status">Loading Sentinel data…</div>;
  if (error) return <div className="state error" role="alert"><AlertTriangle size={18}/><div><b>Sentinel could not load this view</b><p>{error}</p><small>API: {API_BASE}</small>{onRetry && <p><button className="button secondary compact" onClick={onRetry}>Retry</button></p>}</div></div>;
  if (empty) return <div className="state"><CircleHelp size={18}/><span>{emptyText}</span></div>;
  return <>{children}</>;
}
