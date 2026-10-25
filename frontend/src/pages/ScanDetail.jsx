import React, { useState, useEffect } from 'react';
import {
  Activity,
  Bug,
  CheckCircle2,
  FileText,
  Globe,
  Layers,
  Lock,
  RefreshCw,
  Server,
  ArrowRight,
} from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

export default function ScanDetail({ scanId, onSelectFinding, onViewReport }) {
  const [scan, setScan] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [activeTab, setActiveTab] = useState('findings'); // 'findings' or 'endpoints'
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScanData();
    // Auto-poll if scan is in progress
    const interval = setInterval(() => {
      if (scan && (scan.status === 'PENDING' || scan.status === 'DISCOVERING' || scan.status === 'SCANNING')) {
        loadScanData(false);
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  async function loadScanData(showLoading = true) {
    if (showLoading) setLoading(true);
    try {
      const scanData = await api.getScan(scanId);
      setScan(scanData);

      const [eps, vulns] = await Promise.all([
        api.listEndpoints(scanId),
        api.listVulnerabilities(scanId),
      ]);
      setEndpoints(eps);
      setVulnerabilities(vulns);
    } catch (e) {
      console.error('Failed to load scan details:', e);
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  if (loading && !scan) {
    return <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading scan session...</div>;
  }

  if (!scan) {
    return <div style={{ padding: '32px', textAlign: 'center', color: '#fb7185' }}>Scan session not found.</div>;
  }

  const isRunning = scan.status === 'PENDING' || scan.status === 'DISCOVERING' || scan.status === 'SCANNING';

  return (
    <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Scan Header Info Banner */}
      <div
        className="glass-card"
        style={{
          padding: '24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderLeft: '4px solid var(--cyan-primary)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff' }}>Target Assessment</span>
            <StatusBadge status={scan.status} />
            {isRunning && (
              <span style={{ fontSize: '0.8rem', color: 'var(--cyan-primary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <RefreshCw size={12} className="spin" /> Probing in progress...
              </span>
            )}
          </div>
          <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '6px', display: 'flex', gap: '16px' }}>
            <span className="font-mono" style={{ color: 'var(--cyan-primary)' }}>{scan.target_url}</span>
            <span>•</span>
            <span>{endpoints.length} endpoints discovered</span>
            <span>•</span>
            <span>{vulnerabilities.length} findings recorded</span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={() => loadScanData(true)} className="btn-secondary" style={{ padding: '8px 14px', fontSize: '0.82rem' }}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button onClick={() => onViewReport(scan.id)} className="btn-primary" style={{ padding: '8px 16px', fontSize: '0.82rem' }}>
            <FileText size={14} /> View Security Report
          </button>
        </div>
      </div>

      {/* Severity Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => {
          const count = vulnerabilities.filter((v) => (v.severity || '').toUpperCase() === sev).length;
          return (
            <div key={sev} className="glass-card" style={{ padding: '14px', textAlign: 'center' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>{sev}</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: '2px', color: sev === 'CRITICAL' ? '#fb7185' : sev === 'HIGH' ? '#fb923c' : sev === 'MEDIUM' ? '#facc15' : '#60a5fa' }}>
                {count}
              </div>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '12px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
        <button
          onClick={() => setActiveTab('findings')}
          style={{
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'findings' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            padding: '8px 16px',
            color: activeTab === 'findings' ? 'var(--cyan-primary)' : 'var(--text-secondary)',
            fontWeight: 600,
            fontSize: '0.9rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Bug size={16} /> Security Findings ({vulnerabilities.length})
        </button>

        <button
          onClick={() => setActiveTab('endpoints')}
          style={{
            background: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'endpoints' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            padding: '8px 16px',
            color: activeTab === 'endpoints' ? 'var(--cyan-primary)' : 'var(--text-secondary)',
            fontWeight: 600,
            fontSize: '0.9rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Layers size={16} /> Discovered API Surface ({endpoints.length})
        </button>
      </div>

      {/* Tab 1: Findings Table */}
      {activeTab === 'findings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {vulnerabilities.length === 0 ? (
            <div className="glass-card" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
              {isRunning ? 'Running automated security tests against discovered endpoints...' : 'No security vulnerabilities detected.'}
            </div>
          ) : (
            vulnerabilities.map((v) => (
              <div
                key={v.id}
                onClick={() => onSelectFinding(v.id)}
                className="glass-card glass-card-interactive"
                style={{
                  padding: '18px 24px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxWidth: '75%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <SeverityBadge severity={v.severity} score={v.severity_score} />
                    <StatusBadge status={v.status} />
                    {v.cwe_id && (
                      <span className="badge badge-info" style={{ textTransform: 'none' }}>
                        {v.cwe_id}
                      </span>
                    )}
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '1rem', color: '#ffffff' }}>
                    {v.title}
                  </div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {v.description.length > 140 ? `${v.description.substring(0, 140)}...` : v.description}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <button className="btn-secondary" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
                    Inspect Evidence <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Discovered Endpoints Table */}
      {activeTab === 'endpoints' && (
        <div className="glass-card" style={{ padding: '20px', overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '10px 14px' }}>Method</th>
                <th style={{ padding: '10px 14px' }}>Path</th>
                <th style={{ padding: '10px 14px' }}>Auth Required</th>
                <th style={{ padding: '10px 14px' }}>Parameters</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep) => {
                const methodClass = `method-${ep.method.toLowerCase()}`;
                const paramsList = ep.parameters?.params || [];
                return (
                  <tr key={ep.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '12px 14px' }}>
                      <span className={`badge ${methodClass}`} style={{ fontWeight: 700 }}>
                        {ep.method}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', fontWeight: 600, color: '#ffffff' }}>
                      <span className="font-mono">{ep.path}</span>
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      {ep.auth_required ? (
                        <span style={{ color: '#facc15', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.8rem' }}>
                          <Lock size={12} /> Bearer Auth
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Public</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                      {paramsList.length > 0
                        ? paramsList.map((p) => `${p.name} (${p.location})`).join(', ')
                        : 'None'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
