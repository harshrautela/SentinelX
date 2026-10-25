import React from 'react';
import { CheckCircle2, Clock, PlayCircle, XCircle } from 'lucide-react';

export default function StatusBadge({ status }) {
  const st = (status || 'OPEN').toUpperCase();

  const config = {
    FIXED: { class: 'badge-fixed', icon: CheckCircle2, label: 'Fixed / Verified' },
    OPEN: { class: 'badge-open', icon: XCircle, label: 'Open Finding' },
    COMPLETED: { class: 'badge-fixed', icon: CheckCircle2, label: 'Completed' },
    SCANNING: { class: 'badge-low', icon: PlayCircle, label: 'Scanning' },
    DISCOVERING: { class: 'badge-medium', icon: Clock, label: 'Discovering' },
    PENDING: { class: 'badge-info', icon: Clock, label: 'Pending' },
    FAILED: { class: 'badge-critical', icon: XCircle, label: 'Failed' },
  }[st] || { class: 'badge-info', icon: Clock, label: st };

  const Icon = config.icon;

  return (
    <span className={`badge ${config.class}`}>
      <Icon size={12} />
      <span>{config.label}</span>
    </span>
  );
}
