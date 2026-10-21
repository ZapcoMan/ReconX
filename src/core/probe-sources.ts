// 双源探测结果归一与主次判定。
// 主源 = King-CrackX detector（页面侧全量分析，经 content 桥异步回传）；
// 辅源 = ReconX routerProbe（background 同步注入取返回值）。
// 主源识别不出技术栈时辅源升为兜底主源；两路结果始终同时呈现，由人工判断差异。
import type { RouteEntry } from '../types'

export type SourceId = 'king-detector' | 'router-probe'
export type SourceRole = 'primary' | 'auxiliary' | 'fallback' | 'unavailable'
export type FrameworkKind = 'vue' | 'react' | 'unknown'

export interface ProbeView {
  id: SourceId
  label: string
  role: SourceRole
  usable: boolean
  framework: FrameworkKind
  frameworkText: string
  versionText: string
  routerKind: string
  routerBase: string
  detectedBasePath: string
  routes: RouteEntry[]
  routeCount: number
  note: string
}

export interface ProbeCompare {
  primary: ProbeView
  auxiliary: ProbeView
  isFallback: boolean
  divergence: string[]
  headline: string
}

const LABELS: Record<SourceId, string> = {
  'king-detector': 'King-CrackX detector（主）',
  'router-probe': 'ReconX routerProbe（辅）'
}

function frameworkOf(raw: any): FrameworkKind {
  const f = String((raw && raw.framework) || '').toLowerCase()
  if (f.indexOf('vue') === 0) return 'vue'
  if (f.indexOf('react') === 0) return 'react'
  return 'unknown'
}

function routesOf(raw: any): RouteEntry[] {
  const list = raw && Array.isArray(raw.allRoutes) ? raw.allRoutes : []
  return list.filter((r: any) => r && typeof r.path === 'string')
}

function text(v: any): string {
  return v === null || v === undefined || v === '' ? '—' : String(v)
}

function emptyView(id: SourceId): ProbeView {
  return {
    id, label: LABELS[id], role: 'unavailable', usable: false, framework: 'unknown',
    frameworkText: '未识别', versionText: '—', routerKind: '—', routerBase: '—',
    detectedBasePath: '—', routes: [], routeCount: 0, note: ''
  }
}

/** 主源：King detector。未识别时其 framework 仍保留默认 'vue'，需 vueDetected / react 分支佐证 */
export function viewFromDetector(raw: any): ProbeView {
  const v = emptyView('king-detector')
  if (!raw || typeof raw !== 'object') return { ...v, note: '页面未回传分析结果' }
  if (raw.error) return { ...v, note: 'detector 报错：' + String(raw.error) }

  const framework = frameworkOf(raw)
  const claimed = raw.vueDetected === true || framework === 'react'
  const routes = routesOf(raw)
  const usable = raw.routerDetected === true && framework !== 'unknown' && claimed && routes.length > 0

  const version = framework === 'react'
    ? [text(raw.reactVersion), text(raw.routerVersion)].filter((s) => s !== '—').join(' · ')
    : text(raw.vueVersion)

  return {
    ...v, role: usable ? 'primary' : 'unavailable', usable, framework,
    frameworkText: usable ? (framework === 'vue' ? 'Vue' : 'React') : '未识别',
    versionText: usable && version ? version : '—',
    routerKind: usable ? text(raw.routerLib || (framework === 'vue' ? 'Vue Router' : null)) : '—',
    routerBase: usable ? text(raw.routerBase) : '—',
    detectedBasePath: usable ? text(raw.pageAnalysis && raw.pageAnalysis.detectedBasePath) : '—',
    routes: usable ? routes : [], routeCount: usable ? routes.length : 0,
    note: usable ? '' : (raw.routerDetected ? '路由已检出但框架判定不可信' : '未检出前端路由')
  }
}

/** 辅源：routerProbe。framework 为 null 即未识别，无默认值污染 */
export function viewFromProbe(raw: any): ProbeView {
  const v = emptyView('router-probe')
  if (!raw || typeof raw !== 'object') return { ...v, note: 'background 未取得探测结果' }
  if (raw.error) return { ...v, note: 'routerProbe 报错：' + String(raw.error) }

  const framework = frameworkOf(raw)
  const routes = routesOf(raw)
  const usable = framework !== 'unknown' && routes.length > 0

  const version = framework === 'react'
    ? [text(raw.reactVersion), text(raw.reactRouterVersion)].filter((s) => s !== '—').join(' · ')
    : text(raw.vueVersion)

  return {
    ...v, role: 'auxiliary', usable, framework,
    frameworkText: usable ? (framework === 'vue' ? 'Vue' : 'React') : '未识别',
    versionText: usable && version ? version : '—',
    routerKind: usable ? text(raw.routerKind) : '—',
    routerBase: usable ? text(raw.routerBase) : '—',
    detectedBasePath: usable ? text(raw.pageAnalysis && raw.pageAnalysis.detectedBasePath) : '—',
    routes: usable ? routes : [], routeCount: usable ? routes.length : 0,
    note: usable ? '' : '未识别出框架或路由'
  }
}

function compareViews(a: ProbeView, b: ProbeView): string[] {
  const out: string[] = []
  if (a.usable && b.usable) {
    if (a.framework !== b.framework) out.push(`框架判定不一致：${a.label} 判为 ${a.frameworkText}，${b.label} 判为 ${b.frameworkText}`)
    if (a.routerKind !== b.routerKind) out.push(`路由库不一致：${a.label} ${a.routerKind}，${b.label} ${b.routerKind}`)
    if (a.routeCount !== b.routeCount) out.push(`路由条数不一致：${a.label} ${a.routeCount} 条，${b.label} ${b.routeCount} 条（差 ${Math.abs(a.routeCount - b.routeCount)}）`)
    if (a.routerBase !== b.routerBase) out.push(`基础路径不一致：${a.label} ${a.routerBase}，${b.label} ${b.routerBase}`)
    if (a.detectedBasePath !== b.detectedBasePath) out.push(`页面推断路径不一致：${a.label} ${a.detectedBasePath}，${b.label} ${b.detectedBasePath}`)
  }
  if (a.usable && !b.usable) out.push(`辅源无可用结果：${b.note || b.label}`)
  if (!a.usable && b.usable) out.push(`主源无可用结果：${a.note || a.label}`)
  return out
}

/** 汇总两路结果：主源可用则主源为 primary，否则辅源升为 fallback */
export function buildProbeCompare(detectorRaw: any, probeRaw: any): ProbeCompare {
  const detector = viewFromDetector(detectorRaw)
  const probe = viewFromProbe(probeRaw)

  if (detector.usable) {
    detector.role = 'primary'
    probe.role = 'auxiliary'
    return {
      primary: detector, auxiliary: probe, isFallback: false,
      divergence: compareViews(detector, probe),
      headline: `主源：${detector.label}（${detector.frameworkText}）；辅源结果并列展示供交叉核对`
    }
  }

  if (probe.usable) {
    probe.role = 'fallback'
    return {
      primary: probe, auxiliary: detector, isFallback: true,
      divergence: compareViews(detector, probe),
      headline: `主源未识别出技术栈，已改用 ${probe.label} 兜底（${probe.frameworkText}）`
    }
  }

  return {
    primary: detector, auxiliary: probe, isFallback: false,
    divergence: ['两路探测均未识别出可用技术栈'],
    headline: '两路均未识别出前端技术栈，以下结果仅作排障参考'
  }
}
