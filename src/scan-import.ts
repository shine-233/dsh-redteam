/**
 * Scanner-XML ingestion for nmap and Nessus exports. Hand-rolled tolerant
 * tag scanning (machine-generated XML, no entities beyond defaults) so the
 * bundle stays dependency-free. Produces structured results the tool layer
 * maps onto assets/facts/findings/evidence.
 */

export interface ParsedHost {
  address: string
  hostname: string | null
  services: { port: number; protocol: string; name: string; product: string | null }[]
}

export interface ParsedNessusItem {
  host: string
  pluginId: string
  pluginName: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  port: string
  protocol: string
  description: string
  solution: string | null
  output: string | null
  cves: string[]
}

export interface NmapResult {
  kind: 'nmap'
  hosts: ParsedHost[]
}

export interface NessusResult {
  kind: 'nessus'
  hosts: { address: string; name: string | null }[]
  items: ParsedNessusItem[]
}

export type ScanResult = NmapResult | NessusResult

function attr(tag: string, name: string): string | null {
  const m = new RegExp(`${name}="([^"]*)"`).exec(tag)
  return m === null ? null : m[1]!
}

function severityFromNessus(level: string): ParsedNessusItem['severity'] {
  switch (level) {
    case '4': return 'critical'
    case '3': return 'high'
    case '2': return 'medium'
    case '1': return 'low'
    default: return 'info'
  }
}

export function parseNmapXml(xml: string): NmapResult {
  const hosts: ParsedHost[] = []
  const hostBlocks = xml.match(/<host\b[\s\S]*?<\/host>/g) ?? []
  for (const block of hostBlocks) {
    const addrTag = /<address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"[^>]*>/.exec(block)
      ?? /<address[^>]*addr="([^"]+)"[^>]*>/.exec(block)
    if (addrTag === null) continue
    const hostTag = /<hostname[^>]*name="([^"]+)"/.exec(block)
    const services: ParsedHost['services'] = []
    const portBlocks = block.match(/<port\b[\s\S]*?<\/port>/g) ?? []
    for (const pb of portBlocks) {
      if (!/<state[^>]*state="open"/.test(pb)) continue
      const open = /<port\s+protocol="([^"]*)"\s+portid="(\d+)"/.exec(pb)
      if (open === null) continue
      const svc = /<service[^>]*name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?/.exec(pb)
      services.push({
        port: Number(open[2]),
        protocol: open[1]!,
        name: svc?.[1] ?? 'unknown',
        product: svc?.[2] ?? null,
      })
    }
    hosts.push({ address: addrTag[1]!, hostname: hostTag?.[1] ?? null, services })
  }
  if (hosts.length === 0) throw new Error('no <host> blocks found — is this an nmap XML export?')
  return { kind: 'nmap', hosts }
}

export function parseNessusXml(xml: string): NessusResult {
  const hosts: { address: string; name: string | null }[] = []
  const items: ParsedNessusItem[] = []
  const hostBlocks = xml.match(/<ReportHost\b[\s\S]*?<\/ReportHost>/g) ?? []
  for (const block of hostBlocks) {
    const nameAttr = attr(block.match(/<ReportHost[^>]*>/)?.[0] ?? '', 'name')
    let address = nameAttr ?? 'unknown-host'
    let dnsName: string | null = null
    const props = block.match(/<HostProperties>[\s\S]*?<\/HostProperties>/)?.[0] ?? ''
    for (const tag of props.match(/<tag\s+name="([^"]+)"[^>]*>([^<]*)<\/tag>/g) ?? []) {
      const m = /<tag\s+name="([^"]+)"[^>]*>([^<]*)<\/tag>/.exec(tag)
      if (m === null) continue
      if (m[1] === 'host-ip') address = m[2]!
      if (m[1] === 'host-fqdn' || m[1] === 'netbios-name') dnsName = dnsName ?? m[2]!
    }
    hosts.push({ address, name: dnsName })

    const itemBlocks = block.match(/<ReportItem\b[\s\S]*?<\/ReportItem>/g) ?? []
    for (const ib of itemBlocks) {
      const head = /<ReportItem\b([^>]*)>/.exec(ib)?.[1] ?? ''
      const pick = (child: string): string | null =>
        new RegExp(`<${child}>([\\s\\S]*?)</${child}>`).exec(ib)?.[1]?.trim() ?? null
      const cves = [...ib.matchAll(/<cve>(CVE-\d{4}-\d{4,7})<\/cve>/gi)].map((m) => m[1]!.toUpperCase())
      items.push({
        host: address,
        pluginId: attr(head, 'pluginID') ?? '',
        pluginName: attr(head, 'pluginName') ?? '',
        severity: severityFromNessus(attr(head, 'severity') ?? '0'),
        port: attr(head, 'port') ?? '',
        protocol: attr(head, 'protocol') ?? '',
        description: pick('description') ?? '',
        solution: pick('solution'),
        output: pick('plugin_output'),
        cves,
      })
    }
  }
  if (hosts.length === 0) throw new Error('no <ReportHost> blocks found — is this a Nessus XML export?')
  return { kind: 'nessus', hosts, items }
}

export function parseScanXml(format: 'nmap-xml' | 'nessus-xml', xml: string): ScanResult {
  return format === 'nmap-xml' ? parseNmapXml(xml) : parseNessusXml(xml)
}
