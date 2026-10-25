import React, { useState, useEffect } from 'react';
import { FileText, Download, Copy, Check, Terminal, ExternalLink } from 'lucide-react';
import { api } from '../services/api';

export default function Reports({ preselectedScanId }) {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(preselectedScanId || '');
  const [reportFormat, setReportFormat] = useState('MARKDOWN');
  const [reportContent, setReportContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      loadReport(selectedScanId, reportFormat);
    }
  }, [selectedScanId, reportFormat]);

  async function loadScans() {
    try {
      const data = await api.listScans();
      setScans(data);
      if (!selectedScanId && data.length > 0) {
        setSelectedScanId(data[0].id);
      }
    } catch (e) {
      console.error('Failed to load scans:', e);
    }
  }

  async function loadReport(scanId, format) {
    setLoading(true);
    try {
      if (format === 'MARKDOWN') {
        const text = await api.getMarkdownReport(scanId);
        setReportContent(text);
      } else {
        const data = await api.getReport(scanId, 'JSON');
        setReportContent(typeof data.content === 'string' ? data.content : JSON.stringify(data, null, 2));
      }
    } catch (e) {
      setReportContent(`# Error generating report: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  function handleCopy() {
    navigator.clipboard.writeText(reportContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownload() {
    const ext = reportFormat === 'MARKDOWN' ? 'md' : 'json';
    const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinelx-report-${selectedScanId.substring(0, 8)}.${ext}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff' }}>Security Assessment Reports</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '2px' }}>
            Comprehensive, evidence-backed penetration testing reports suitable for security review.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={handleCopy} className="btn-secondary" style={{ padding: '8px 14px', fontSize: '0.82rem' }}>
            {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
            <span>{copied ? 'Copied!' : 'Copy to Clipboard'}</span>
          </button>
          <button onClick={handleDownload} className="btn-primary" style={{ padding: '8px 16px', fontSize: '0.82rem' }}>
            <Download size={14} /> Download Report
          </button>
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 600 }}>Select Scan:</span>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            style={{
              background: 'var(--bg-card)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              padding: '8px 14px',
              borderRadius: '6px',
              fontSize: '0.85rem',
              outline: 'none',
              minWidth: '320px',
            }}
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_url} — {new Date(s.created_at).toLocaleDateString()} ({s.status})
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setReportFormat('MARKDOWN')}
            style={{
              background: reportFormat === 'MARKDOWN' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
              border: reportFormat === 'MARKDOWN' ? '1px solid var(--cyan-primary)' : '1px solid var(--border-subtle)',
              color: reportFormat === 'MARKDOWN' ? 'var(--cyan-primary)' : 'var(--text-secondary)',
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Markdown Format
          </button>
          <button
            onClick={() => setReportFormat('JSON')}
            style={{
              background: reportFormat === 'JSON' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
              border: reportFormat === 'JSON' ? '1px solid var(--cyan-primary)' : '1px solid var(--border-subtle)',
              color: reportFormat === 'JSON' ? 'var(--cyan-primary)' : 'var(--text-secondary)',
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Structured JSON
          </button>
        </div>
      </div>

      {/* Report Viewer Content */}
      <div className="glass-card" style={{ padding: '24px' }}>
        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Generating report...</div>
        ) : (
          <pre
            style={{
              background: 'var(--bg-code)',
              padding: '24px',
              borderRadius: '8px',
              fontSize: '0.85rem',
              color: '#e2e8f0',
              overflowX: 'auto',
              whiteSpace: 'pre-wrap',
              lineHeight: 1.6,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {reportContent}
          </pre>
        )}
      </div>
    </div>
  );
}
