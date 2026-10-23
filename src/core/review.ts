/**
 * 复核工作清单与误报反哺（纯逻辑，展示/复核层，绝不改动原始命中或内置规则）。
 *
 * 思路：把分散在三处的风险命中（JS 发现 / 敏感接口 / 主动探测）汇成一张按置信降序的
 * 待复核清单，每条带置信档位与"是否已标误报"状态；并把误报标记跨站点聚合，找出
 * 在多个站点都被判误报的规则，提示"疑似过报"——但只提示、最多一键升为全站忽略，
 * 绝不自动改内置规则、也不跨站静默隐藏真漏洞（站点隔离原则不变）。
 *
 * 无 chrome / DOM 依赖，纯函数便于回归测试。
 */
import { confidenceOf, type Confidence } from './confidence'
import { fpSignature, fpMapKey, describeFp, type FpKind } from './false-positive'

export interface ReviewItem {
  kind: FpKind
  key: string
  label: string
  detail: string
  severity: string
  confidence: Confidence
  flagged: boolean
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function worstSeverity(list: string[]): string {
  let best = 'info'
  for (const s of list) {
    const i = SEV_ORDER.indexOf(String(s || '').toLowerCase())
    if (i >= 0 && i < SEV_ORDER.indexOf(best)) best = SEV_ORDER[i]
  }
  return best
}

function isFlagged(fpSet: Set<string>, host: string, kind: FpKind, key: string): boolean {
  const sig = fpSignature(kind, key)
  return fpSet.has(fpMapKey(host, sig, 'site')) || fpSet.has(fpMapKey('*', sig, 'global'))
}

function shortName(url: string): string {
  const parts = String(url).split('/')
  return parts[parts.length - 1] || url
}

/** 汇总三类命中为按置信降序的复核清单；fpSet 为当前误报集合（fpSet(list) 生成） */
export function buildReviewWorklist(bundle: any, host: string, fpSet: Set<string>): ReviewItem[] {
  const items: ReviewItem[] = []
  const js = (bundle && bundle.js) || {}
  // JS 发现按规则 id 聚合：同一规则跨多文件命中 → 来源数 + 总处数，喂给置信度
  const byId = new Map<string, { sevs: string[]; urls: Set<string>; count: number; name: string }>()
  ;[].concat(js.findings || [], js.inlineFindings || []).forEach((f: any) => {
    if (!f) return
    const id = String(f.id || f.name || 'unknown')
    const e = byId.get(id) || { sevs: [], urls: new Set<string>(), count: 0, name: String(f.name || id) }
    e.sevs.push(f.severity)
    if (f.url && f.url !== 'inline') e.urls.add(f.url)
    e.count += typeof f.count === 'number' ? f.count : 1
    byId.set(id, e)
  })
  byId.forEach((e, id) => {
    const sev = worstSeverity(e.sevs)
    const flagged = isFlagged(fpSet, host, 'finding', id)
    const src = e.urls.size
      ? Array.from(e.urls).slice(0, 2).map(shortName).join(', ') + (e.urls.size > 2 ? ' +' + (e.urls.size - 2) : '')
      : 'inline'
    items.push({ kind: 'finding', key: id, label: e.name, detail: src + ' · ' + e.count + ' 处', severity: sev, confidence: confidenceOf({ severity: sev, sourceCount: e.urls.size || 1, occurrences: e.count, flagged }), flagged })
  })
  ;((bundle && bundle.security && bundle.security.sensitiveApis) || []).forEach((a: any) => {
    if (!a || !a.path) return
    const sev = String(a.riskLevel || '').toLowerCase()
    const flagged = isFlagged(fpSet, host, 'api', a.path)
    items.push({ kind: 'api', key: a.path, label: a.category || a.path, detail: a.path + (a.source ? ' · ' + a.source : ''), severity: sev, confidence: confidenceOf({ severity: sev, flagged }), flagged })
  })
  ;((bundle && bundle.probes && bundle.probes.results) || []).forEach((p: any) => {
    if (!p || !p.matched || !p.path) return
    const sev = String(p.severity || '').toLowerCase()
    const flagged = isFlagged(fpSet, host, 'probe', p.path)
    items.push({ kind: 'probe', key: p.path, label: p.desc || p.path, detail: p.path + ' → ' + p.status, severity: sev, confidence: confidenceOf({ severity: sev, status: p.status, flagged }), flagged })
  })
  items.sort((x, y) => y.confidence.score - x.confidence.score || x.kind.localeCompare(y.kind) || String(x.key).localeCompare(String(y.key)))
  return items
}

export interface WorklistCounts { total: number; high: number; medium: number; low: number; suspect: number; flagged: number }

export function worklistCounts(items: ReviewItem[]): WorklistCounts {
  const out: WorklistCounts = { total: (items || []).length, high: 0, medium: 0, low: 0, suspect: 0, flagged: 0 }
  for (const it of items || []) { out[it.confidence.tier]++; if (it.flagged) out.flagged++ }
  return out
}

export interface OverFireRule { sig: string; kind: string; key: string; hostCount: number; hosts: string[] }

/**
 * 跨站点聚合 site 维度的误报标记：同一规则签名在 >=minHosts 个不同主机被判误报，
 * 且尚未全站忽略的，列为"疑似过报"候选。已全站化的不再提示。
 */
export function overFireRules(fpList: string[], minHosts = 2): OverFireRule[] {
  const bySig = new Map<string, Set<string>>()
  const globalSigs = new Set<string>()
  for (const mk of fpList || []) {
    const d = describeFp(mk)
    const sig = d.kind + ':' + d.key
    if (d.scope === 'global') { globalSigs.add(sig); continue }
    if (!bySig.has(sig)) bySig.set(sig, new Set<string>())
    if (d.host) bySig.get(sig)!.add(d.host)
  }
  const out: OverFireRule[] = []
  bySig.forEach((hosts, sig) => {
    if (globalSigs.has(sig)) return
    if (hosts.size >= minHosts) {
      const c = sig.indexOf(':')
      out.push({ sig, kind: sig.slice(0, c), key: sig.slice(c + 1), hostCount: hosts.size, hosts: Array.from(hosts).sort() })
    }
  })
  out.sort((a, b) => b.hostCount - a.hostCount || a.sig.localeCompare(b.sig))
  return out
}
