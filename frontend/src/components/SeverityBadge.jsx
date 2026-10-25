import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function SeverityBadge({ severity, score }) {
  const sev = (severity || 'INFO').toUpperCase();

  const config = {
    CRITICAL: { class: 'badge-critical', icon: ShieldAlert, label: 'Critical' },
    HIGH: { class: 'badge-high', icon: AlertTriangle, label: 'High' },
    MEDIUM: { class: 'badge-medium', icon: AlertCircle, label: 'Medium' },
    LOW: { class: 'badge-low', icon: Info, label: 'Low' },
    INFO: { class: 'badge-info', icon: ShieldCheck, label: 'Info' },
  }[sev] || { class: 'badge-info', icon: Info, label: sev };

  const Icon = config.icon;

  return (
    <span className={`badge ${config.class}`}>
      <Icon size={12} />
      <span>{config.label}</span>
      {score !== undefined && score !== null && (
        <span style={{ opacity: 0.8, marginLeft: '2px' }}>{score.toFixed(1)}</span>
      )}
    </span>
  );
}
