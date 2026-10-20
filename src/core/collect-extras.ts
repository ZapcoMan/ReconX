// 只读三能力组装（自 lib/collect-extras.js 迁移为 ES 模块）：routes/api/security/classified/riskNote
import { buildLiveApis, finalize } from './api-extract'
import { buildRouteUrlList } from './route-urls'
import { performSecurityAudit } from './security-audit'
import { rankItems } from './url-classify'
import type { RouterProbeResult } from '../types'
export interface ComputeExtrasContext {
  tab: { url: string }
  host: string
  js?: { endpoints?: Record<string, any>; sourcemaps?: Array<{ from: string; map: string }> }
  routerInfo?: RouterProbeResult | Record<string, any>
  links?: { endpoints?: Array<{ url: string }> }
}
export function computeExtras(ctx: ComputeExtrasContext): Record<string, any> {
  const tab = ctx.tab, host = ctx.host, js = ctx.js || {}
  const routerInfo = (ctx.routerInfo || {}) as Record<string, any>
  const links = ctx.links || { endpoints: [] }
  let origin = ''
  try { origin = new URL(tab.url).origin } catch { /* */ }
  const liveApis = buildLiveApis(routerInfo.perf || [])
  const livePathnames = liveApis.map((a) => { try { return new URL(a.url).pathname } catch { return a.path } })
  const staticApis = finalize((js.endpoints || {}) as Record<string, any>, livePathnames, origin)
  const sourceMaps = (js.sourcemaps || []).map((m) => { let mu = m.map; try { mu = new URL(m.map, m.from).href } catch { /* */ } return { scriptUrl: m.from, mapUrl: mu } })
  let routesList: Array<Record<string, any>> = routerInfo.allRoutes && routerInfo.allRoutes.length ? routerInfo.allRoutes : []
  let anchorFallback = false
  if (!routesList.length) {
    const sp: Record<string, number> = {}
    ;(routerInfo.anchorLinks || []).forEach((href: string) => {
      try { const u = new URL(href); if (u.hostname === host && !sp[u.pathname]) { sp[u.pathname] = 1; routesList.push({ path: u.pathname, name: '', meta: {} }) } } catch { /* */ }
    })
    anchorFallback = routesList.length > 0
  }
  let routeBuild: any = { items: [], sectionTitle: '标准 URL', routerBase: null }
  try { routeBuild = buildRouteUrlList({ routes: routesList, currentUrl: tab.url, routerBase: routerInfo.routerBase, detectedBasePath: null }) } catch { /* */ }
  const security = performSecurityAudit({ pageUrl: tab.url, liveApis, staticApis, routes: routesList, sourceMaps })
  let classified: any[] = []
  try { classified = rankItems(links.endpoints || []).filter((e) => e.level).slice(0, 500) } catch { /* */ }
  const routes = { framework: routerInfo.framework, vueVersion: routerInfo.vueVersion, reactVersion: routerInfo.reactVersion, reactRouterVersion: routerInfo.reactRouterVersion, next: !!routerInfo.next, routerDetected: !!routerInfo.routerDetected, routerKind: routerInfo.routerKind || null, routerBase: routeBuild.routerBase || routerInfo.routerBase || null, allRoutesCount: routesList.length, allRoutes: routesList.slice(0, 300), fullUrls: (routeBuild.items || []).slice(0, 300), sectionTitle: routeBuild.sectionTitle, anchorFallback, error: routerInfo.error || null }
  const api = { liveApisCount: liveApis.length, liveApis: liveApis.slice(0, 300), staticApisCount: staticApis.length, uncalledCount: staticApis.filter((a) => !a.called).length, staticApis: staticApis.slice(0, 400), sourceMaps }
  let riskNote: Record<string, any> | null = null
  const or = security.summary.overallRisk
  if (or === 'critical' || or === 'high') riskNote = { level: or, category: '前端审计', summary: '审计整体风险 ' + or + '：敏感 API ' + security.summary.sensitiveApiCount + ' 个，未保护路由线索 ' + security.summary.unprotectedRoutes + ' 个' }
  return { routes, api, security, classified, riskNote }
}
