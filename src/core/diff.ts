/**
 * 两次采集对比的纯逻辑（展示层，绝不改动任一原始 bundle）。
 *
 * 设计原则：
 *   - 只对同一主机的两份采集做增删对比；跨主机结果 sameHost=false，仍返回各类目并集但不做误导汇总；
 *   - 以稳定 key 判定：路径类用 path，JS 发现类用规则 id；
 *   - 只产出 added / removed / kept 三态，命中原文一律保留在各自 bundle 内。
 *
 * 无 chrome / DOM 依赖，纯函数便于回归测试。
 */

export interface CategoryDiff {
  name: string
  added: string[]
  removed: string[]
  kept: number
}

export interface BundleDiff {
  sameHost: boolean
  host: string
  olderAt: number
  newerAt: number
  categories: CategoryDiff[]
  addedTotal: number
  removedTotal: number
}

function uniq(list: string[]): string[] {
  return Array.from(new Set(list))
}

const CATS: Array<{ name: string; ex: (b: any) => string[] }> = [
  { name: '端点', ex: (b) => uniq(((b && b.links && b.links.endpoints) || []).map((e: any) => e && e.path).filter(Boolean)) },
  { name: '静态 API', ex: (b) => uniq(((b && b.api && b.api.staticApis) || []).map((x: any) => x && x.path).filter(Boolean)) },
  { name: '路由', ex: (b) => uniq(((b && b.routes && b.routes.allRoutes) || []).map((r: any) => r && r.path).filter(Boolean)) },
  { name: '敏感接口', ex: (b) => uniq(((b && b.security && b.security.sensitiveApis) || []).map((x: any) => x && x.path).filter(Boolean)) },
  { name: 'JS 发现', ex: (b) => uniq([].concat((b && b.js && b.js.findings) || [], (b && b.js && b.js.inlineFindings) || []).map((x: any) => x && x.id).filter(Boolean)) },
  { name: '探测命中', ex: (b) => uniq(((b && b.probes && b.probes.results) || []).filter((p: any) => p && p.matched).map((p: any) => p && p.path).filter(Boolean)) }
]

/** 以 older 为基线、newer 为现状，逐类目算出新增 / 消失 / 保留 */
export function diffBundles(older: any, newer: any): BundleDiff {
  const host = (newer && newer.meta && newer.meta.host) || ''
  const olderHost = (older && older.meta && older.meta.host) || ''
  const sameHost = !!olderHost && olderHost === host
  const categories: CategoryDiff[] = CATS.map((c) => {
    const a = c.ex(older)
    const b = c.ex(newer)
    const sa = new Set(a)
    const sb = new Set(b)
    const added = b.filter((x) => !sa.has(x)).sort()
    const removed = a.filter((x) => !sb.has(x)).sort()
    let kept = 0
    for (const x of a) if (sb.has(x)) kept++
    return { name: c.name, added, removed, kept }
  })
  return {
    sameHost,
    host,
    olderAt: (older && older.meta && older.meta.collectedAt) || 0,
    newerAt: (newer && newer.meta && newer.meta.collectedAt) || 0,
    categories,
    addedTotal: categories.reduce((s, c) => s + c.added.length, 0),
    removedTotal: categories.reduce((s, c) => s + c.removed.length, 0)
  }
}

/** 供 UI 决定是否值得展示"消失"项：全为 0 时的空摘要 */
export function diffSummary(d: BundleDiff): string {
  if (!d.sameHost) return '两份结果主机不同，仅作并列展示。'
  if (!d.addedTotal && !d.removedTotal) return '两次采集在对比维度上无增删。'
  return `新增 ${d.addedTotal} 项 · 消失 ${d.removedTotal} 项`
}
