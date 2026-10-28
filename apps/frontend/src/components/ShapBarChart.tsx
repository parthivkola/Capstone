import type { ApiRecord } from '../hooks/useSentinelData';

interface ShapFeature {
  feature: string;
  value: number;
  raw_value?: number;
}

export function ShapBarChart({ features, title, maxFeatures = 12 }: {
  features: ApiRecord[];
  title?: string;
  maxFeatures?: number;
}) {
  const rows: ShapFeature[] = features
    .map(item => ({
      feature: String(item.feature || item.name || 'feature'),
      value: Number(item.shap_value ?? item.log_odds_contribution_toward_prediction ?? 0),
      raw_value: item.value !== undefined ? Number(item.value) : undefined,
    }))
    .filter(item => Number.isFinite(item.value))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, maxFeatures);

  if (!rows.length) {
    return <p className="footnote">No SHAP attributions available for this prediction.</p>;
  }

  const maxAbs = Math.max(...rows.map(item => Math.abs(item.value)), 1e-9);
  const width = 480;
  const rowHeight = 32;
  const labelWidth = 160;
  const barZone = width - labelWidth - 80;
  const height = rows.length * rowHeight + 44;
  const center = labelWidth + barZone / 2;

  return (
    <figure className="shap-chart">
      {title ? <figcaption>{title}</figcaption> : null}
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="SHAP feature attribution waterfall">
        {/* Axis label */}
        <text x={center} y={14} textAnchor="middle" fontSize={9} fill="#8a96a8" fontWeight="700">
          ← BENIGN &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; INTRUSION →
        </text>
        {/* Zero line */}
        <line x1={center} y1={20} x2={center} y2={height - 8} stroke="#c8d0db" strokeWidth="1" strokeDasharray="3,3" />

        {rows.map((item, index) => {
          const y = 24 + index * rowHeight;
          const barMax = barZone / 2 - 8;
          const barWidth = (Math.abs(item.value) / maxAbs) * barMax;
          const isPositive = item.value >= 0;
          const barX = isPositive ? center : center - barWidth;
          const fill = isPositive ? '#d05046' : '#3571b5';
          const fillLight = isPositive ? '#f7e6e4' : '#e6eef7';
          const valueLabel = item.value > 0
            ? `+${item.value.toFixed(4)}`
            : item.value.toFixed(4);

          return (
            <g key={`${item.feature}-${index}`}>
              {/* Row background */}
              <rect x={0} y={y - 2} width={width} height={rowHeight - 2} fill={index % 2 === 0 ? '#fafbfc' : '#fff'} />
              {/* Feature label */}
              <text x={labelWidth - 8} y={y + 14} textAnchor="end" fontSize={9} fill="#3a4a60" fontFamily="Inter,system-ui,sans-serif">
                {item.feature.length > 20 ? item.feature.slice(0, 18) + '…' : item.feature}
              </text>
              {/* Bar background */}
              <rect x={barX} y={y + 4} width={Math.max(barWidth, 2)} height={16} rx={3} fill={fillLight} />
              {/* Bar fill */}
              <rect x={barX} y={y + 4} width={Math.max(barWidth, 2)} height={16} rx={3} fill={fill} opacity={0.85} />
              {/* SHAP value label */}
              <text
                x={isPositive ? barX + Math.max(barWidth, 2) + 5 : barX - 5}
                y={y + 16}
                textAnchor={isPositive ? 'start' : 'end'}
                fontSize={8.5}
                fill={fill}
                fontWeight="600"
              >
                {valueLabel}
              </text>
              {/* Raw value if present */}
              {item.raw_value !== undefined && (
                <text x={width - 4} y={y + 16} textAnchor="end" fontSize={8} fill="#9aa3b0">
                  val={Number.isFinite(item.raw_value) ? item.raw_value.toFixed(2) : '—'}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div style={{ display: 'flex', gap: '16px', margin: '8px 0 4px', alignItems: 'center' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#3571b5' }}>
          <span style={{ display: 'inline-block', width: 12, height: 12, borderRadius: 3, background: '#3571b5' }} />
          Pushes toward BENIGN
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#d05046' }}>
          <span style={{ display: 'inline-block', width: 12, height: 12, borderRadius: 3, background: '#d05046' }} />
          Pushes toward INTRUSION
        </span>
      </div>
      <p className="footnote">
        Exact linear SHAP attributions for the registered logistic regression model. Values are log-odds contributions
        from each standardized feature. The model uses {features.length} features total; top {maxFeatures} shown by |SHAP|.
      </p>
    </figure>
  );
}

/** Inline mini SHAP summary — top-3 contributors as colored chips */
export function ShapSummary({ features }: { features: ApiRecord[] }) {
  const top3 = features
    .map(item => ({
      feature: String(item.feature || ''),
      value: Number(item.shap_value ?? item.log_odds_contribution_toward_prediction ?? 0),
    }))
    .filter(item => Number.isFinite(item.value) && item.feature)
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 3);

  if (!top3.length) return null;
  return (
    <span style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
      {top3.map((f, i) => (
        <span
          key={i}
          title={`${f.feature}: SHAP ${f.value > 0 ? '+' : ''}${f.value.toFixed(4)}`}
          style={{
            display: 'inline-block',
            background: f.value >= 0 ? '#fdecea' : '#e8f0fb',
            color: f.value >= 0 ? '#b84040' : '#2a5fa8',
            borderRadius: '4px',
            padding: '2px 6px',
            fontSize: '9px',
            fontWeight: 600,
            border: `1px solid ${f.value >= 0 ? '#f0c4c0' : '#c0d4f0'}`,
          }}
        >
          {f.feature.length > 15 ? f.feature.slice(0, 13) + '…' : f.feature}
          {' '}
          {f.value > 0 ? '+' : ''}{f.value.toFixed(3)}
        </span>
      ))}
    </span>
  );
}
