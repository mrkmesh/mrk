export function short(value: string, head = 10, tail = 6): string {
  if (!value || value.length <= head + tail + 1) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export function dateTime(timestamp: number | null | undefined): string {
  if (!timestamp) return '—'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
    timeZone: 'UTC',
  }).format(new Date(timestamp * 1000)) + ' UTC'
}

export function relativeTime(timestamp: number | null | undefined): string {
  if (!timestamp) return '—'
  const seconds = timestamp - Math.floor(Date.now() / 1000)
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  if (Math.abs(seconds) < 60) return formatter.format(seconds, 'second')
  const minutes = Math.round(seconds / 60)
  if (Math.abs(minutes) < 60) return formatter.format(minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (Math.abs(hours) < 48) return formatter.format(hours, 'hour')
  return formatter.format(Math.round(hours / 24), 'day')
}

export function displayEnum(value: string): string {
  return value.replaceAll('_', ' ').toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase())
}

export function duration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds))
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  if (days) return `${days}d ${hours}h`
  if (hours) return `${hours}h ${minutes}m`
  if (minutes) return `${minutes}m ${seconds % 60}s`
  return `${seconds}s`
}
