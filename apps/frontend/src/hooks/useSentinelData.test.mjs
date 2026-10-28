import test from 'node:test';
import assert from 'node:assert/strict';
import React, { act } from 'react';
import TestRenderer from 'react-test-renderer';
import { createServer } from 'vite';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
globalThis.window = { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) };
let vite, useSentinelData;
let mountedRoot;
test.before(async()=>{ vite=await createServer({configFile:new URL('../../vite.config.ts',import.meta.url).pathname,server:{middlewareMode:true,hmr:false},appType:'custom'}); ({useSentinelData}=await vite.ssrLoadModule('/src/hooks/useSentinelData.ts')); });
test.afterEach(async()=>{ if(mountedRoot){await act(async()=>mountedRoot.unmount());mountedRoot=undefined;} });
test.after(async()=>{await vite?.close()});

function fixtureFetch({fail=false,statusLabel='CONNECTED'}={}) {
  const calls=[];
  globalThis.fetch=async url=>{calls.push(String(url)); if(fail) return {ok:false,status:503,json:async()=>({error:{message:'service unavailable'}})};
    const p=new URL(String(url)).pathname;
    let body={};
    if(p.endsWith('/status')) body={controller:statusLabel};
    else if(p.endsWith('/live/status')) body={controller:statusLabel,telemetry:'STALE',live_detection:'UNAVAILABLE'};
    else if(p.endsWith('/datasets')) body={prepared_dataset:{files:[]}};
    else if(p.endsWith('/models')) body={models:[]};
    else if(p.endsWith('/inference/schema')) body={models:[]};
    else if(p.endsWith('/detections')&&p.includes('limit=100')) body={items:[{id:'live-1'}]};
    else if(p.endsWith('/live/ledger')) body={items:[]};
    else if(p.endsWith('/experiments')||p.endsWith('/sessions')||p.endsWith('/telemetry/audits')||p.endsWith('/audit')||p.endsWith('/detections')) body={items:[],page:{total:0}};
    return {ok:true,status:200,json:async()=>body};
  };
  return calls;
}
function payloadFor(url,label='CONNECTED') { const p=new URL(url).pathname; if(p.endsWith('/live/status'))return {controller:label,telemetry:'STALE',live_detection:'UNAVAILABLE'}; if(p.endsWith('/status'))return {controller:label}; if(p.endsWith('/datasets'))return {prepared_dataset:{files:[]}}; if(p.endsWith('/models')||p.endsWith('/inference/schema'))return {models:[]}; if(p.endsWith('/detections')&&p.includes('limit=100'))return {items:[{id:'live-1'}]}; return {items:[],page:{total:0}}; }
async function flush(){ await act(async()=>{await new Promise(resolve=>setTimeout(resolve,0))}); }
function Harness({onValue}) { const value=useSentinelData(5000); onValue(value); return React.createElement('output',null,value.loading?'loading':value.error||value.status?.controller||'empty'); }

test('hook moves from loading to successful API state',async()=>{
  const requests=[]; globalThis.fetch=url=>new Promise(resolve=>requests.push(()=>resolve({ok:true,status:200,json:async()=>payloadFor(String(url))}))); const values=[]; let root;
  await act(async()=>{root=TestRenderer.create(React.createElement(Harness,{onValue:v=>values.push(v)}));}); mountedRoot=root;
  assert.equal(root.toJSON().children[0],'loading'); await flush();
  await act(async()=>{requests.forEach(resolve=>resolve()); await new Promise(resolve=>setTimeout(resolve,0));});
  assert.equal(values.at(-1).status.controller,'CONNECTED'); assert.equal(values.at(-1).liveStatus.telemetry,'STALE');
  await act(async()=>root.unmount()); mountedRoot=undefined;
});
test('hook reports API failures instead of converting them to empty success',async()=>{
  fixtureFetch({fail:true}); let value; let root;
  await act(async()=>{root=TestRenderer.create(React.createElement(Harness,{onValue:v=>value=v}))}); mountedRoot=root; await flush();
  assert.match(value.error,/service unavailable/); assert.equal(value.status,null); await act(async()=>root.unmount()); mountedRoot=undefined;
});
test('manual refresh supersedes an in-flight response and stale response cannot overwrite it',async()=>{
  let resolvers=[]; globalThis.fetch=()=>new Promise(resolve=>resolvers.push(resolve)); let value; let root;
  await act(async()=>{root=TestRenderer.create(React.createElement(Harness,{onValue:v=>value=v}))}); mountedRoot=root;
  await act(async()=>{void value.refresh();});
  const respond=(label)=>({ok:true,status:200,json:async()=>({controller:label})});
  // Resolve newer request first; remaining responses belong to the superseded batch.
  for(const resolve of resolvers.slice(12)) resolve(respond('NEW'));
  await flush();
  for(const resolve of resolvers.slice(0,12)) resolve(respond('OLD'));
  await flush();
  assert.equal(value.status?.controller,'NEW'); await act(async()=>root.unmount()); mountedRoot=undefined;
});
test('polling interval is stable across refreshes and is cleared on unmount',async()=>{
  fixtureFetch(); const original=globalThis.window; const intervals=new Map(); let next=0; let cleared=[];
  globalThis.window={setInterval:fn=>{const id=++next;intervals.set(id,fn);return id},clearInterval:id=>{cleared.push(id);intervals.delete(id)}};
  let value; let root; await act(async()=>{root=TestRenderer.create(React.createElement(Harness,{onValue:v=>value=v}))}); mountedRoot=root; await flush();
  const installed=intervals.size; assert.equal(installed,1);
  await act(async()=>{await value.refresh()}); assert.equal(intervals.size,1,'refresh must not restart the polling timer');
  const poll=[...intervals.values()][0]; await act(async()=>{poll();await new Promise(resolve=>setTimeout(resolve,0))}); assert.equal(intervals.size,1);
  await act(async()=>root.unmount()); mountedRoot=undefined; assert.equal(intervals.size,0); assert.deepEqual(cleared,[1]);
  globalThis.window=original;
});
test('unmount prevents late requests from publishing state',async()=>{
  let resolve; globalThis.fetch=()=>new Promise(r=>{resolve=r}); let updates=0; let root;
  await act(async()=>{root=TestRenderer.create(React.createElement(Harness,{onValue:()=>updates++}))}); mountedRoot=root; const before=updates;
  await act(async()=>root.unmount()); mountedRoot=undefined; resolve({ok:true,status:200,json:async()=>({items:[]})}); await flush();
  assert.equal(updates,before);
});
