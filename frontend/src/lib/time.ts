// The API sends UTC timestamps. Older servers sent them without a zone
// ("2026-11-09T21:47:32.644496"), which `new Date()` reads as local time.
// Treat a timestamp with no zone as UTC so every viewer sees the same instant.
const HAS_ZONE = /(Z|[+-]\d{2}:?\d{2})$/i;

export function parseApiDate(value: string): Date {
  const trimmed = value.trim();
  const hasTime = trimmed.includes('T') || trimmed.includes(' ');
  return new Date(hasTime && !HAS_ZONE.test(trimmed) ? `${trimmed}Z` : trimmed);
}
