import type { ReactNode } from 'react';
import {
  Activity, Boxes, ClipboardList, Database, FileClock,
  LayoutDashboard, Menu, Network, Shield, ShieldAlert, Zap,
} from 'lucide-react';

export type PageName =
  | 'Overview' | 'Live monitoring' | 'Run Offline Inference' | 'Predictions'
  | 'Sessions' | 'Project data' | 'Telemetry' | 'Models' | 'Audit log' | 'Mitigation';

const navigation = [
  { name: 'Overview', icon: LayoutDashboard },
  { name: 'Live monitoring', icon: Activity },
  { name: 'Run Offline Inference', icon: Zap },
  { name: 'Predictions', icon: ShieldAlert },
  { name: 'Sessions', icon: ClipboardList },
  { name: 'Project data', icon: Database },
  { name: 'Telemetry', icon: Network },
  { name: 'Models', icon: Boxes },
  { name: 'Audit log', icon: FileClock },
  { name: 'Mitigation', icon: Shield },
] satisfies { name: PageName; icon: typeof LayoutDashboard }[];

export function AppShell({
  page, setPage, mobile, setMobile, predictionCount, refresh, controllerStatus, children,
}: {
  page: PageName;
  setPage: (page: PageName) => void;
  mobile: boolean;
  setMobile: (open: boolean) => void;
  predictionCount: number;
  refresh: () => void;
  controllerStatus?: string;
  children: ReactNode;
}) {
  const ctrlColor =
    controllerStatus === 'CONNECTED' ? '#3ec875' :
    controllerStatus === 'STALE' ? '#e6a83f' :
    '#e06060';

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobile ? 'open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><Shield size={19} /></span>
          <span>
            <b>SENTINEL</b>
            <small>SDN DEFENCE</small>
          </span>
        </div>
        <div className="mode-label">OPERATIONS WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map(({ name, icon: Icon }) => (
            <button
              key={name}
              aria-current={page === name ? 'page' : undefined}
              className={`nav-item ${page === name ? 'selected' : ''}`}
              onClick={() => { setPage(name); setMobile(false); }}
            >
              <Icon size={17} />
              <span>{name}</span>
              {name === 'Predictions' && predictionCount > 0 && (
                <em>{predictionCount}</em>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="live-dot" style={{ background: ctrlColor }} />
          SDN Defence Appliance
          <small>
            Controller: {controllerStatus || 'Unknown'}
          </small>
          <small style={{ marginTop: '4px', color: '#6a7a8a', fontSize: '9px' }}>
            Explainable · Bounded · Reversible
          </small>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button
            className="menu-button"
            onClick={() => setMobile(!mobile)}
            aria-label="Toggle navigation"
          >
            <Menu size={20} />
          </button>
          <div className="crumb">
            Sentinel <span>/</span> {page}
          </div>
          <div className="top-actions">
            <span className="demo-badge">
              <i style={{ background: ctrlColor }} />
              {' '}
              {controllerStatus === 'CONNECTED' ? 'LIVE' : 'LOCAL REVIEW'}
            </span>
            <button className="icon-button" onClick={refresh} aria-label="Refresh data" title="Refresh all data">
              <Activity size={17} />
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
