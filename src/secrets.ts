/**
 * Secret masking for surfaces that leave the record system (session
 * projections, markdown/json reports). Raw values stay only in storage.
 */

/** Show head/tail for long values; short values collapse entirely. */
export function maskSecret(secret: string): string {
  if (secret === '') return ''
  if (secret.length <= 8) return '••••'
  return `${secret.slice(0, 2)}••••${secret.slice(-2)}`
}
