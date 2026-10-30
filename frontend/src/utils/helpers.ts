import { SeverityLevel } from '../types';

export function getSeverityBadgeClass(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-red-500/15 text-red-400 border border-red-500/30';
    case 'HIGH':
      return 'bg-orange-500/15 text-orange-400 border border-orange-500/30';
    case 'MEDIUM':
    case 'SUSPICIOUS':
      return 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30';
    case 'LOW':
      return 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30';
    case 'BENIGN':
    default:
      return 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30';
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
