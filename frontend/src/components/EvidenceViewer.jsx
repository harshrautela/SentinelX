import React, { useState } from 'react';
import { Terminal, Shield, ArrowRight, Eye, Code } from 'lucide-react';

export default function EvidenceViewer({ evidenceList }) {
  const [activeTab, setActiveTab] = useState(0);

  if (!evidenceList || evidenceList.length === 0) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
        No technical evidence items attached.
      </div>
    );
  }

  const current = evidenceList[activeTab] || evidenceList[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Evidence Selection Tabs if multiple items */}
      {evidenceList.length > 1 && (
        <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          {evidenceList.map((ev, idx) => (
            <button
              key={ev.id || idx}
              onClick={() => setActiveTab(idx)}
              style={{
                background: activeTab === idx ? 'rgba(6, 182, 212, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                border: activeTab === idx ? '1px solid var(--cyan-primary)' : '1px solid var(--border-subtle)',
                color: activeTab === idx ? 'var(--cyan-primary)' : 'var(--text-secondary)',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              Evidence Artifact #{idx + 1}
            </button>
          ))}
        </div>
      )}

      {/* Observation Callout */}
      <div
        style={{
          background: 'rgba(6, 182, 212, 0.08)',
          borderLeft: '4px solid var(--cyan-primary)',
          padding: '12px 16px',
          borderRadius: '4px',
          fontSize: '0.9rem',
          lineHeight: 1.6,
        }}
      >
        <div style={{ fontWeight: 600, color: 'var(--cyan-primary)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Eye size={16} /> Verified Technical Observation
        </div>
        <div style={{ color: 'var(--text-primary)' }}>{current.observation}</div>
      </div>

      {/* Side-by-Side: Original (Baseline) vs Test (Attack) */}
      <div style={{ display: 'grid', gridTemplateColumns: current.original_request ? '1fr 1fr' : '1fr', gap: '16px' }}>
        {/* Baseline Block */}
        {current.original_request && (
          <div className="glass-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                1. Baseline Request
              </span>
              <span className="badge badge-info" style={{ textTransform: 'none' }}>
                Status: {current.original_status || 200}
              </span>
            </div>

            <div style={{ background: 'var(--bg-code)', padding: '10px', borderRadius: '6px', overflowX: 'auto' }}>
              <div style={{ color: '#38bdf8', fontSize: '0.8rem', fontWeight: 600 }}>
                {current.original_request.method} {current.original_request.url}
              </div>
            </div>

            {current.original_response_excerpt && (
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Response Excerpt:</div>
                <pre
                  style={{
                    background: 'var(--bg-code)',
                    padding: '10px',
                    borderRadius: '6px',
                    fontSize: '0.78rem',
                    color: '#e2e8f0',
                    maxHeight: '220px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {current.original_response_excerpt}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* Attack / Test Request Block */}
        <div className="glass-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', border: '1px solid rgba(244, 63, 94, 0.25)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fb7185' }}>
              {current.original_request ? '2. Modified / Probe Request' : 'Test Request'}
            </span>
            <span className={`badge ${current.test_status >= 200 && current.test_status < 300 ? 'badge-critical' : 'badge-info'}`} style={{ textTransform: 'none' }}>
              Status: {current.test_status}
            </span>
          </div>

          {current.test_request && current.test_request.url && (
            <div style={{ background: 'var(--bg-code)', padding: '10px', borderRadius: '6px', overflowX: 'auto' }}>
              <div style={{ color: '#f43f5e', fontSize: '0.8rem', fontWeight: 600 }}>
                {current.test_request.method} {current.test_request.url}
              </div>
            </div>
          )}

          {current.test_response_excerpt && (
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Response Excerpt:</div>
              <pre
                style={{
                  background: 'var(--bg-code)',
                  padding: '10px',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  color: '#e2e8f0',
                  maxHeight: '220px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {current.test_response_excerpt}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
