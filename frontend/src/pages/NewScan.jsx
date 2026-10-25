import React, { useState } from 'react';
import { Play, Shield, Globe, FileCode, Check, AlertCircle } from 'lucide-react';
import { api } from '../services/api';

export default function NewScan({ onScanCreated }) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8001');
  const [openapiUrl, setOpenapiUrl] = useState('http://localhost:8001/openapi.json');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const scan = await api.createScan({
        target_url: targetUrl.trim(),
        openapi_url: openapiUrl.trim() || null,
      });
      onScanCreated(scan.id);
    } catch (err) {
      setError(err.message || 'Failed to initiate scan.');
    } finally {
      setSubmitting(false);
    }
  }

  function applyPreset(presetTarget, presetSpec) {
    setTargetUrl(presetTarget);
    setOpenapiUrl(presetSpec);
  }

  return (
    <div style={{ padding: '32px', maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ffffff' }}>Initiate VAPT Scan</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '4px' }}>
          Configure target API URL and OpenAPI/Swagger schema location to execute automated vulnerability assessment.
        </p>
      </div>

      {error && (
        <div
          style={{
            background: 'var(--sev-critical-bg)',
            border: '1px solid var(--sev-critical-border)',
            padding: '14px 18px',
            borderRadius: '8px',
            color: '#fb7185',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '0.9rem',
          }}
        >
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Preset Target Banner */}
      <div
        className="glass-card"
        style={{
          padding: '16px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'rgba(6, 182, 212, 0.05)',
          border: '1px solid var(--border-accent)',
        }}
      >
        <div>
          <div style={{ fontWeight: 600, color: 'var(--cyan-primary)', fontSize: '0.88rem' }}>
            Local Test Preset: VulnBank API (:8001)
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Intentionally vulnerable banking API target with BOLA, SQLi, sensitive data leakage, and JWT flaws.
          </div>
        </div>
        <button
          type="button"
          onClick={() => applyPreset('http://localhost:8001', 'http://localhost:8001/openapi.json')}
          className="btn-secondary"
          style={{ padding: '6px 14px', fontSize: '0.8rem', whiteSpace: 'nowrap' }}
        >
          <Check size={14} /> Apply Preset
        </button>
      </div>

      {/* Main Scan Form */}
      <form onSubmit={handleSubmit} className="glass-card" style={{ padding: '28px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            Target Base URL <span style={{ color: '#f43f5e' }}>*</span>
          </label>
          <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-code)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0 14px' }}>
            <Globe size={18} color="var(--text-muted)" />
            <input
              type="url"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8001"
              className="font-mono"
              style={{
                width: '100%',
                background: 'transparent',
                border: 'none',
                padding: '12px 10px',
                color: '#ffffff',
                fontSize: '0.9rem',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Must resolve to local or private authorized IP/hostname (e.g. localhost, 127.0.0.1, vulnerable-api).
          </div>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            OpenAPI Specification URL (Optional)
          </label>
          <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-code)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0 14px' }}>
            <FileCode size={18} color="var(--text-muted)" />
            <input
              type="text"
              value={openapiUrl}
              onChange={(e) => setOpenapiUrl(e.target.value)}
              placeholder="http://localhost:8001/openapi.json"
              className="font-mono"
              style={{
                width: '100%',
                background: 'transparent',
                border: 'none',
                padding: '12px 10px',
                color: '#ffffff',
                fontSize: '0.9rem',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            If omitted, SentinelX automatically probes standard endpoints (/openapi.json, /swagger.json).
          </div>
        </div>

        {/* Security / Legal Scope Notice */}
        <div
          style={{
            padding: '14px',
            borderRadius: '6px',
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.8rem',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}
        >
          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '2px' }}>
            Authorized Testing Scope Notice
          </div>
          SentinelX strictly validates target containment to protect against unintended SSRF or out-of-scope testing.
          Testing executes controlled verification payloads with rate limiting caps.
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="btn-primary"
          style={{ justifyContent: 'center', padding: '14px', fontSize: '0.95rem' }}
        >
          {submitting ? (
            <span>Initiating Discovery & Security Probes...</span>
          ) : (
            <>
              <Play size={16} fill="currentColor" /> Launch Automated VAPT Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}
