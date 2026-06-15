export function formatDate(isoString) {
  if (!isoString) return 'Unknown date'
  try {
    const date = new Date(isoString)
    return date.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return isoString
  }
}

export function getHighestRisk(summary) {
  if (!summary) return null
  if (summary.High > 0) return 'High'
  if (summary.Medium > 0) return 'Medium'
  if (summary.Low > 0) return 'Low'
  if (summary.Informational > 0) return 'Informational'
  return null
}
