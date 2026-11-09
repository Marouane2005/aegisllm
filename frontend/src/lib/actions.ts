// One place for action colors, so the stat cards, chart and badges agree.
export const ACTION_HEX: Record<string, string> = {
  allowed: '#16a34a', // green-600
  masked: '#ca8a04', // yellow-600
  blocked: '#dc2626', // red-600
  rate_limited: '#9333ea', // purple-600
};

export const ACTION_FALLBACK_HEX = '#6b7280'; // gray-500

export const ACTION_BADGE: Record<string, string> = {
  allowed: 'bg-green-100 text-green-800',
  masked: 'bg-yellow-100 text-yellow-800',
  blocked: 'bg-red-100 text-red-800',
  rate_limited: 'bg-purple-100 text-purple-800',
};

export const ACTION_LABEL: Record<string, string> = {
  allowed: 'Allowed',
  masked: 'Masked',
  blocked: 'Blocked',
  rate_limited: 'Rate limited',
};
