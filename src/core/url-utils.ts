export function getAllInSiteKey(url: string | undefined): string {
  try {
    const parsed = new URL(url as string)
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
      return ''
    }
    return parsed.hostname.toLowerCase()
  } catch {
    return ''
  }
}