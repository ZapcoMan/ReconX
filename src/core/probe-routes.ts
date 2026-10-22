// 统一「主动探测」中的前端路由探测（自 lib/probe-routes.js 迁移为 ES 模块）
// 仅对识别为 Vue/React 的站点：枚举路由 → 拼完整 URL → 逐个 GET 探测可达性。
// 这是「探测」语义（HTTP 可达性核验），不做 router 接管/守卫清除。在 background(SW) 上下文调用。
import { buildRouteUrlList } from './route-urls'
import type { RouterProbeResult } from '../types'

export interface RouteProbeItem {
  path: string
  url: string
  status: number
  bytes: number
  error: string | null
}

export async function probeRoutes(ctx: { routerInfo: RouterProbeResult; currentUrl: string }): Promise<Record<string, any>> {
  const ri = (ctx.routerInfo || {}) as RouterProbeResult
  const fw = ri.framework
  if (fw !== 'vue' && fw !== 'react') {
    return {
      applicable: false,
      framework: fw || null,
      reason: fw ? '框架为 ' + fw + '，非 Vue/React，跳过前端路由探测' : '未识别到 Vue/React，跳过前端路由探测'
    }
  }
  const routes = ri.allRoutes && ri.allRoutes.length ? ri.allRoutes : []
  let built = { items: [] as Array<{ path?: string; url: string }>, sectionTitle: '标准 URL' }
  try {
    // 同样传入辅源页面链接推断的 base，history 模式下带基础路径的站点才能拼对探测 URL
    built = buildRouteUrlList({ routes, currentUrl: ctx.currentUrl, routerBase: ri.routerBase, detectedBasePath: (ri.pageAnalysis && ri.pageAnalysis.detectedBasePath) || null })
  } catch {
    /* ignore */
  }
  const items = (built.items || []).slice(0, 40)
  const probes: RouteProbeItem[] = []
  for (let i = 0; i < items.length; i++) {
    const it = items[i]
    let status = 0
    let bytes = 0
    let err: string | null = null
    try {
      const ctrl = new AbortController()
      const to = setTimeout(() => {
        try {
          ctrl.abort()
        } catch {
          /* ignore */
        }
      }, 5000)
      const r = await fetch(it.url, { credentials: 'omit', redirect: 'follow', signal: ctrl.signal })
      clearTimeout(to)
      status = r.status
      try {
        const t = await r.text()
        bytes = t.length
      } catch {
        /* ignore */
      }
    } catch (e: any) {
      err = String((e && e.message) || e)
    }
    probes.push({ path: it.path || '', url: it.url, status, bytes, error: err })
    await new Promise((res) => setTimeout(res, 200))
  }
  // routeFullUrls：全量拼接结果（不受探测 40 条上限约束），security-report 的「路由完整 URL」章节由此生效
  return { applicable: true, framework: fw, routerKind: ri.routerKind || null, routerDetected: !!ri.routerDetected, total: items.length, sectionTitle: built.sectionTitle, routeFullUrls: built.items, routeProbes: probes }
}
