import type { ApiRecord } from '../hooks/useSentinelData';
import { AsyncState } from '../components/common/AsyncState';
import { get, post } from '../api.mjs';
import { useState } from 'react';

export function SessionsPage({loading,error,refresh,sessions}:{loading:boolean;error:string|null;refresh:()=>void;sessions:ApiRecord[]}) {
 const [busy,setBusy]=useState(false); const [message,setMessage]=useState<string|null>(null);
 const start=async()=>{setBusy(true);setMessage(null);try{await post('/sessions',{});await refresh()}catch(e){setMessage(e instanceof Error?e.message:String(e))}finally{setBusy(false)}};
 const stop=async(id:string)=>{setBusy(true);setMessage(null);try{await post(`/sessions/${id}/stop`);await refresh()}catch(e){setMessage(e instanceof Error?e.message:String(e))}finally{setBusy(false)}};
 const exportRun=async(id:string)=>{try{const body=await get(`/sessions/${id}/export`);const url=URL.createObjectURL(new Blob([JSON.stringify(body,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`sentinel-${id}.json`;a.click();URL.revokeObjectURL(url)}catch(e){setMessage(e instanceof Error?e.message:String(e))}};
 return <AsyncState loading={loading} error={error} onRetry={refresh}><section className="panel"><h1>Sessions</h1><p>Demo sessions store synthetic fixtures only; they are not live detections.</p><button className="button primary" disabled={busy} onClick={()=>void start()}>{busy?'Working…':'Start demo session'}</button>{message&&<p role="alert">{message}</p>}{sessions.length?<div className="table-wrap"><table><thead><tr><th>Session</th><th>Created</th><th>State</th><th>Source</th><th>Actions</th></tr></thead><tbody>{sessions.map((s,i)=>{const id=String(s.id||'');return <tr key={id||i}><td>{id||'—'}</td><td>{String(s.created_at||'—')}</td><td>{String(s.status||'UNKNOWN')}</td><td>SYNTHETIC_FIXTURE</td><td><button className="button secondary compact" disabled={!id} onClick={()=>void exportRun(id)}>Export</button>{s.status==='RUNNING'&&<button className="button danger compact" disabled={busy} onClick={()=>void stop(id)}>Stop</button>}</td></tr>})}</tbody></table></div>:<div className="state">No sessions have been created.</div>}</section></AsyncState>;
}
