import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

let vite;
test.before(async () => { vite = await createServer({ configFile: new URL('../vite.config.ts', import.meta.url).pathname, server: { middlewareMode: true, hmr: false }, appType: 'custom' }); });
test.after(async () => { await vite?.close(); });
async function render(modulePath, component, props) {
  const loaded = await vite.ssrLoadModule(modulePath);
  return renderToStaticMarkup(React.createElement(loaded[component], props));
}

test('overview reports separate controller, telemetry, model and detection readiness', async () => {
  const html = await render('/src/pages/OverviewPage.tsx', 'OverviewPage', { loading:false,error:null,refresh:()=>{},status:{controller:'STALE'},liveStatus:{controller:'STALE',telemetry:'UNAVAILABLE',live_detection:'UNAVAILABLE',reason:'no active epoch'},models:[{model_id:'stage7-live-logistic-preliminary',status:'TRAINED_UNAPPROVED_PRELIMINARY'}],detections:[],onNavigate:()=>{} });
  assert.match(html,/STALE/); assert.match(html,/UNAVAILABLE/); assert.match(html,/No offline predictions recorded/);
});
test('pages expose initial loading and API error states with retry', async () => {
  const loading = await render('/src/pages/TelemetryPage.tsx','TelemetryPage',{loading:true,error:null,refresh:()=>{},liveStatus:null,rows:[]});
  assert.match(loading,/Loading Sentinel data/);
  const failed = await render('/src/pages/DetectionsPage.tsx','DetectionsPage',{loading:false,error:'connection refused',refresh:()=>{},rows:[]});
  assert.match(failed,/connection refused/); assert.match(failed,/Retry/);
});
test('empty, stale telemetry and unapproved model are rendered truthfully', async () => {
  const telemetry = await render('/src/pages/TelemetryPage.tsx','TelemetryPage',{loading:false,error:null,refresh:()=>{},liveStatus:{telemetry:'STALE'},rows:[]});
  assert.match(telemetry,/STALE/); assert.match(telemetry,/No telemetry audit records/);
  const model = await render('/src/pages/ModelPage.tsx','ModelPage',{loading:false,error:null,refresh:()=>{},models:[{model_id:'live-candidate',status:'TRAINED_UNAPPROVED_PRELIMINARY',inference_enabled:false}]});
  assert.match(model,/TRAINED_UNAPPROVED_PRELIMINARY/); assert.match(model,/not approved/);
});
test('mitigation view never implies enforcement or rollback confirmation', async () => {
  const html = await render('/src/pages/MitigationPage.tsx','MitigationPage',{state:'DISABLED',reason:'No endpoint'});
  assert.match(html,/Live mitigation is disabled/); assert.match(html,/Submission, independent confirmation, expiry, and verified rollback are separate/); assert.doesNotMatch(html,/Traffic blocked/);
});
