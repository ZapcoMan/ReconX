// 采集历史：索引与全量分离存。索引 bundleHistory 只放轻量摘要（结果页下拉要一次读完），
// 每份完整 bundle 单独占一个 bundle:<id> 键，只有切到那一条时才读它。
// 扩展未申请 unlimitedStorage，配额约 10MB，因此索引有硬性条数上限，超出的最旧条目连同其全量键一起丢弃。
import type { ReconBundle } from '../types'

export interface BundleMeta {
  id: string
  host: string
  url: string
  collectedAt: number
  endpoints: number
  routes: number
  findings: number
  probes: boolean
  truncated: boolean
}

export const HISTORY_LIMIT = 20
export const HISTORY_INDEX_KEY = 'bundleHistory'
export const bundleKey = (id: string): string => 'bundle:' + id

/** 同一主机重复采集要能区分，故 id 带时间戳；同时保留可读前缀方便在 DevTools 里辨认 */
export function makeBundleId(bundle: Pick<ReconBundle, 'meta'>): string {
  const host = String((bundle.meta && bundle.meta.host) || 'site').replace(/[^a-zA-Z0-9._-]/g, '-').slice(-40)
  return host + '@' + Number((bundle.meta && bundle.meta.collectedAt) || Date.now()).toString(36)
}

export function metaOf(bundle: any): BundleMeta {
  const m = bundle.meta || {}
  return {
    id: m.id || makeBundleId(bundle),
    host: m.host || '',
    url: m.url || '',
    collectedAt: Number(m.collectedAt) || 0,
    endpoints: (bundle.links && bundle.links.total) || 0,
    routes: (bundle.routes && bundle.routes.allRoutesCount) || 0,
    findings: ((bundle.js && bundle.js.findings) || []).length + ((bundle.js && bundle.js.inlineFindings) || []).length,
    probes: !!(bundle.probes && bundle.probes.performed),
    truncated: !!bundle.storageTruncated
  }
}

/** 新条目插到最前并按 collectedAt 倒序，同 id 覆盖旧条目；超出上限的尾部由调用方删除其全量键 */
export function addToIndex(index: BundleMeta[] | null | undefined, meta: BundleMeta, limit = HISTORY_LIMIT): { next: BundleMeta[]; dropped: BundleMeta[] } {
  const rest = (index || []).filter((m) => m && m.id !== meta.id)
  const all = [meta, ...rest].sort((a, b) => b.collectedAt - a.collectedAt)
  return { next: all.slice(0, limit), dropped: all.slice(limit) }
}

export function removeFromIndex(index: BundleMeta[] | null | undefined, id: string): BundleMeta[] {
  return (index || []).filter((m) => m && m.id !== id)
}

export function findInIndex(index: BundleMeta[] | null | undefined, id: string): BundleMeta | null {
  return (index || []).find((m) => m && m.id === id) || null
}

export function describeMeta(m: BundleMeta): string {
  const t = m.collectedAt ? new Date(m.collectedAt).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '未知时间'
  return `${t} · ${m.host} · 端点 ${m.endpoints} · 路由 ${m.routes} · 发现 ${m.findings}${m.probes ? ' · 已探测' : ''}${m.truncated ? ' · 截断副本' : ''}`
}
