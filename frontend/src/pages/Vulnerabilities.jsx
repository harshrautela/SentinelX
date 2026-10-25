import React, { useState, useEffect } from 'react';
import { Bug, Filter, ArrowRight, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

export default function Vulnerabilities({ onSelectFinding }) {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFindings();
  }, [severityFilter, statusFilter]);

  async function loadFindings() {
    setLoading(true);
    try {
      const data = await api.listVulnerabilities(
        null,
        severityFilter || null,
        statusFilter || null
      );
      setVulnerabilities(data);
    } catch (e) {
      console.error('Failed to load vulnerabilities:', e);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff' }}>Vulnerability Findings</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '2px' }}>
            Verified security flaws across evaluated REST APIs.
          </p>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            <Filter size={14} /> Filter:
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              background: 'var(--bg-card)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '0.82rem',
              outline: 'none',
            }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              background: 'var(--bg-card)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '0.82rem',
              outline: 'none',
            }}
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="FIXED">Fixed</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading findings...</div>
      ) : vulnerabilities.length === 0 ? (
        <div className="glass-card" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
          No findings match the current filter criteria.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {vulnerabilities.map((v) => (
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
                  {v.description}
                </div>
              </div>

              <button className="btn-secondary" style={{ padding: '6px 14px', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                View Evidence <ArrowRight size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
