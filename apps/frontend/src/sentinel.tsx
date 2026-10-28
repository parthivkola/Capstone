import { useState } from 'react';
import { AppShell, type PageName } from './components/layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { DetectionsPage } from './pages/DetectionsPage';
import { TelemetryPage } from './pages/TelemetryPage';
import { ModelPage } from './pages/ModelPage';
import { MitigationPage } from './pages/MitigationPage';
import { useSentinelData } from './hooks/useSentinelData';
import { SessionsPage } from './pages/SessionsPage';
import { ProjectDataPage } from './pages/ProjectDataPage';
import { OfflineInferencePage } from './pages/OfflineInferencePage';

export default function App() {
  const [page, setPage] = useState<PageName>('Overview');
  const [mobile, setMobile] = useState(false);
  const data = useSentinelData();

  const controllerStatus = String(data.liveStatus?.controller || data.status?.controller || 'UNKNOWN');

  let content;
  switch (page) {
    case 'Overview':
      content = (
        <OverviewPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          liveStatus={data.liveStatus}
          models={data.models}
          detections={data.detections}
          onNavigate={setPage}
        />
      );
      break;
    case 'Predictions':
      content = (
        <DetectionsPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          rows={[...data.liveScores, ...data.detections]}
        />
      );
      break;
    case 'Live monitoring':
      content = (
        <DetectionsPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          rows={data.liveScores}
        />
      );
      break;
    case 'Telemetry':
      content = (
        <TelemetryPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          liveStatus={data.liveStatus}
          rows={data.telemetry}
        />
      );
      break;
    case 'Models':
      content = (
        <ModelPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          models={data.models}
        />
      );
      break;
    case 'Sessions':
      content = (
        <SessionsPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          sessions={data.sessions}
        />
      );
      break;
    case 'Project data':
      content = (
        <ProjectDataPage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          datasets={data.datasets}
          experiments={data.experiments}
        />
      );
      break;
    case 'Run Offline Inference':
      content = (
        <OfflineInferencePage
          loading={data.loading}
          error={data.error}
          refresh={data.refresh}
          datasets={data.datasets}
          models={data.models}
          schema={data.schema}
        />
      );
      break;
    case 'Mitigation':
      content = (
        <MitigationPage
          state={String(data.liveStatus?.mitigation || 'DISABLED')}
          reason={String(data.liveStatus?.mitigation_reason || 'Live mitigation is currently disabled. An active controller connection and validated detection evidence are required.')}
          liveStatus={data.liveStatus}
          mitigationActions={data.mitigationActions}
          mitigationPolicy={data.mitigationPolicy}
          refresh={data.refresh}
        />
      );
      break;
    default:
      content = (
        <section className="panel">
          <h1>{page}</h1>
          <p>This workspace view is not included in the operations summary.</p>
          <button className="button secondary" onClick={() => setPage('Overview')}>
            Return to overview
          </button>
        </section>
      );
  }

  return (
    <AppShell
      page={page}
      setPage={setPage}
      mobile={mobile}
      setMobile={setMobile}
      predictionCount={data.detections.length}
      refresh={() => void data.refresh()}
      controllerStatus={controllerStatus}
    >
      {content}
    </AppShell>
  );
}
