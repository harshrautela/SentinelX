import React, { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  Bug,
  CheckCircle2,
  Globe,
  PlusCircle,
  ShieldAlert,
  Terminal,
  ArrowRight,
} from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

export default function Dashboard({ onNavigate, onSelectScan }) {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    totalEndpoints: 0,
    totalRequests: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    openFindings: 0,
    fixedFindings: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  async function loadDashboardData() {
    setLoading(true);
    try {
      const scanList = await api.listScans(0, 10);
      setScans(scanList);

      const allVulns = await api.listVulnerabilities();

      let endpointsCount = 0;
      let requestsCount = 0;
      scanList.forEach((s) => {
        endpointsCount += s.total_endpoints || 0;
        requestsCount += s.total_requests || 0;
      });

      const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
      };
      let openCount = 0;
      let fixedCount = 0;

      allVulns.forEach((v) => {
        const sev = (v.severity || 'INFO').toUpperCase();
        if (counts[sev] !== undefined) counts[sev]++;
        if (v.status === 'FIXED') fixedCount++;
        else openCount++;
      });

      setStats({
        totalScans: scanList.length,
        totalEndpoints: endpointsCount,
        totalRequests: requestsCount,
        critical: counts.CRITICAL,
        high: counts.HIGH,
        medium: counts.MEDIUM,
        low: counts.LOW,
        openFindings: openCount,
        fixedFindings: fixedCount,
      });
    } catch (e) {
      console.error('Failed to load dashboard:', e);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner / Hero */}
      <div
        className="glass-card"
        style={{
          padding: '24px 28px',
          background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%)',
          border: '1px solid var(--border-accent)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyan-primary)', fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase' }}>
            <Activity size={16} /> API Security & Vulnerability Intelligence
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff', marginTop: '6px' }}>
            Automated API VAPT Engine Ready
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '4px', maxWidth: '650px' }}>
            Discover OpenAPI surfaces, execute controlled behavioral security probes (BOLA, SQLi, Auth Bypass, Data Exposure), and verify reproducible evidence.
          </p>
        </div>
        <button
          onClick={() => onNavigate('new-scan')}
          className="btn-primary"
          style={{ whiteSpace: 'nowrap' }}
        >
          <PlusCircle size={16} /> Launch New Scan
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
            Total Scans Run
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff', marginTop: '6px' }}>
            {stats.totalScans}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>
            Authorized Sessions
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
            Endpoints Analyzed
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--cyan-primary)', marginTop: '6px' }}>
            {stats.totalEndpoints}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>
            OpenAPI Operations
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
            Open Findings
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f43f5e', marginTop: '6px' }}>
            {stats.openFindings}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>
            Requiring Remediation
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
            Verified Fixed
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#10b981', marginTop: '6px' }}>
            {stats.fixedFindings}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px' }}>
            Confirmed via Retesting
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="glass-card" style={{ padding: '20px' }}>
        <div style={{ fontWeight: 600, fontSize: '0.95rem', color: '#ffffff', marginBottom: '16px' }}>
          Finding Severity Distribution
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          <div style={{ background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-border)', padding: '12px', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', color: '#fb7185', fontWeight: 600 }}>CRITICAL</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#fb7185' }}>{stats.critical}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SQLi, RCE</div>
          </div>
          <div style={{ background: 'var(--sev-high-bg)', border: '1px solid var(--sev-high-border)', padding: '12px', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', color: '#fb923c', fontWeight: 600 }}>HIGH</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#fb923c' }}>{stats.high}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>BOLA, Auth Bypass, Leak</div>
          </div>
          <div style={{ background: 'var(--sev-medium-bg)', border: '1px solid var(--sev-medium-border)', padding: '12px', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', color: '#facc15', fontWeight: 600 }}>MEDIUM</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#facc15' }}>{stats.medium}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Headers, JWT, Rate Limit</div>
          </div>
          <div style={{ background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)', padding: '12px', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', color: '#60a5fa', fontWeight: 600 }}>LOW / INFO</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#60a5fa' }}>{stats.low}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Hardening gaps</div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>Recent Security Scans</h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Latest sessions</span>
        </div>

        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading scan history...</div>
        ) : scans.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No scans performed yet. Click "Launch New Scan" to assess your API!
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 14px' }}>Status</th>
                  <th style={{ padding: '10px 14px' }}>Target URL</th>
                  <th style={{ padding: '10px 14px' }}>Endpoints</th>
                  <th style={{ padding: '10px 14px' }}>Executed At</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr
                    key={s.id}
                    style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}
                  >
                    <td style={{ padding: '12px 14px' }}>
                      <StatusBadge status={s.status} />
                    </td>
                    <td style={{ padding: '12px 14px', fontWeight: 600, color: '#ffffff' }}>
                      <span className="font-mono">{s.target_url}</span>
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-secondary)' }}>
                      {s.total_endpoints} operations
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        onClick={() => onSelectScan(s.id)}
                        className="btn-secondary"
                        style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                      >
                        Inspect Results <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
