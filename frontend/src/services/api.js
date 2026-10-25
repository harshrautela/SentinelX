/**
 * SentinelX API Service Client
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

async function handleResponse(res) {
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || `Request failed with status ${res.status}`);
  }
  return res.json();
}

export const api = {
  // --- Scans ---
  async listScans(skip = 0, limit = 50) {
    const res = await fetch(`${API_BASE}/api/v1/scans?skip=${skip}&limit=${limit}`);
    return handleResponse(res);
  },

  async getScan(scanId) {
    const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}`);
    return handleResponse(res);
  },

  async createScan(data) {
    const res = await fetch(`${API_BASE}/api/v1/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  // --- Endpoints ---
  async listEndpoints(scanId) {
    const url = scanId
      ? `${API_BASE}/api/v1/endpoints?scan_id=${scanId}`
      : `${API_BASE}/api/v1/endpoints`;
    const res = await fetch(url);
    return handleResponse(res);
  },

  // --- Vulnerabilities ---
  async listVulnerabilities(scanId = null, severity = null, status = null) {
    const params = new URLSearchParams();
    if (scanId) params.append('scan_id', scanId);
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);

    const res = await fetch(`${API_BASE}/api/v1/vulnerabilities?${params.toString()}`);
    return handleResponse(res);
  },

  async getVulnerability(vulnerabilityId) {
    const res = await fetch(`${API_BASE}/api/v1/vulnerabilities/${vulnerabilityId}`);
    return handleResponse(res);
  },

  async retestVulnerability(vulnerabilityId) {
    const res = await fetch(`${API_BASE}/api/v1/vulnerabilities/${vulnerabilityId}/retest`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  // --- Reports ---
  async getReport(scanId, format = 'JSON') {
    const res = await fetch(`${API_BASE}/api/v1/reports/scan/${scanId}?format=${format}`);
    return handleResponse(res);
  },

  async getMarkdownReport(scanId) {
    const res = await fetch(`${API_BASE}/api/v1/reports/scan/${scanId}/markdown`);
    if (!res.ok) throw new Error('Failed to fetch markdown report');
    return res.text();
  },

  // --- Health ---
  async getSystemHealth() {
    const res = await fetch(`${API_BASE}/health`).catch(() => null);
    if (!res || !res.ok) return { status: 'offline' };
    return res.json();
  },
};
