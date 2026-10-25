import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import Vulnerabilities from './pages/Vulnerabilities';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import Reports from './pages/Reports';

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState(null);

  function handleSelectScan(scanId) {
    setSelectedScanId(scanId);
    setCurrentPage('scan-detail');
  }

  function handleScanCreated(scanId) {
    setSelectedScanId(scanId);
    setCurrentPage('scan-detail');
  }

  function handleSelectFinding(vulnerabilityId) {
    setSelectedVulnerabilityId(vulnerabilityId);
    setCurrentPage('vulnerability-detail');
  }

  function handleViewReport(scanId) {
    setSelectedScanId(scanId);
    setCurrentPage('reports');
  }

  const pageTitles = {
    dashboard: { title: 'Security Dashboard', subtitle: 'Real-time API posture & vulnerability metrics' },
    'new-scan': { title: 'New VAPT Scan', subtitle: 'Target configuration and discovery launch' },
    'scan-detail': { title: 'Scan Execution & Findings', subtitle: 'Live probe observations and discovered operations' },
    vulnerabilities: { title: 'Vulnerabilities Directory', subtitle: 'All verified security findings across scans' },
    'vulnerability-detail': { title: 'Technical Evidence & Retesting', subtitle: 'Inspect reproducible attack proof and verify remediation' },
    reports: { title: 'VAPT Security Reports', subtitle: 'Executive and technical penetration test deliverables' },
  };

  const currentMeta = pageTitles[currentPage] || pageTitles.dashboard;

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      {/* Sidebar */}
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflowY: 'auto' }}>
        <Header
          title={currentMeta.title}
          subtitle={currentMeta.subtitle}
        />

        <main style={{ flex: 1 }}>
          {currentPage === 'dashboard' && (
            <Dashboard
              onNavigate={(page) => setCurrentPage(page)}
              onSelectScan={handleSelectScan}
            />
          )}

          {currentPage === 'new-scan' && (
            <NewScan onScanCreated={handleScanCreated} />
          )}

          {currentPage === 'scan-detail' && (
            <ScanDetail
              scanId={selectedScanId}
              onSelectFinding={handleSelectFinding}
              onViewReport={handleViewReport}
            />
          )}

          {currentPage === 'vulnerabilities' && (
            <Vulnerabilities onSelectFinding={handleSelectFinding} />
          )}

          {currentPage === 'vulnerability-detail' && (
            <VulnerabilityDetail
              vulnerabilityId={selectedVulnerabilityId}
              onBack={() => setCurrentPage(selectedScanId ? 'scan-detail' : 'vulnerabilities')}
            />
          )}

          {currentPage === 'reports' && (
            <Reports preselectedScanId={selectedScanId} />
          )}
        </main>
      </div>
    </div>
  );
}
