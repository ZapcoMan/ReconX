// 只读框架/路由探测（自 lib/router-probe.js 迁移为 TS；注入 MAIN world 执行）
// 对齐 King detector 的只读探测深度；全程只读，仅返回结构数据，不含任何接管/守卫清除/meta 改写。
// 自包含单函数：所有辅助函数内联，便于 chrome.scripting.executeScript({ func }) 序列化注入。
import type { RouterProbeResult, RouteEntry } from '../types'

export function routerProbe(): RouterProbeResult {
  function hasOwn(o: any, k: string): boolean {
    return Object.prototype.hasOwnProperty.call(o, k)
  }
  function safeMeta(m: any): Record<string, any> {
    if (!m || typeof m !== 'object') return {}
    const o: Record<string, any> = {}
    for (const k in m) {
      try {
        const v = m[k], t = typeof v
        if (t === 'string' || t === 'number' || t === 'boolean') o[k] = v
        else if (Array.isArray(v)) o[k] = v.filter((z: any) => ['string', 'number', 'boolean'].includes(typeof z))
        else if (v && t === 'object' && v.constructor === Object) {
          const flat: Record<string, any> = {}
          for (const kk in v) if (hasOwn(v, kk) && ['string', 'number', 'boolean'].includes(typeof v[kk])) flat[kk] = v[kk]
          o[k] = flat
        }
      } catch { /* */ }
    }
    return o
  }
  function joinPath(base: string, path?: string): string {
    if (!path) return base || '/'
    if (path.charAt(0) === '/') return path
    if (!base || base === '/') return '/' + path
    return (base.charAt(base.length - 1) === '/' ? base.slice(0, -1) : base) + '/' + path
  }
  function findKeyByPrefix(el: any, prefix: string): string | null {
    for (const k in el) if (k.indexOf(prefix) === 0) return k
    return null
  }
  function findVueRoot(): any {
    const queue: Array<{ node: any; depth: number }> = [{ node: document.body, depth: 0 }]
    while (queue.length) {
      const it = queue.shift() as { node: any; depth: number }
      if (!it || it.depth > 1000) break
      const el = it.node
      if (el.__vue_app__ || el.__vue__ || el._vnode) return el
      if (el.nodeType === 1 && el.childNodes) for (let i = 0; i < el.childNodes.length; i++) queue.push({ node: el.childNodes[i], depth: it.depth + 1 })
    }
    return null
  }
  function getVueVersion(root: any): string {
    let v = (root.__vue_app__ && root.__vue_app__.version) || (root.__vue__ && root.__vue__.$root && root.__vue__.$root.$options && root.__vue__.$root.$options._base && root.__vue__.$root.$options._base.version)
    if (!v || v === 'unknown') {
      const w = window as any
      if (w.Vue && w.Vue.version) v = w.Vue.version
      else if (w.__VUE_DEVTOOLS_GLOBAL_HOOK__ && w.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue) v = w.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version
    }
    return v || 'unknown'
  }
  function findVueRouter(root: any): any {
    try {
      if (root.__vue_app__) {
        const app = root.__vue_app__
        if (app.config && app.config.globalProperties && app.config.globalProperties.$router) return app.config.globalProperties.$router
        const inst = app._instance
        if (inst && inst.appContext && inst.appContext.config && inst.appContext.config.globalProperties && inst.appContext.config.globalProperties.$router) return inst.appContext.config.globalProperties.$router
        if (inst && inst.ctx && inst.ctx.$router) return inst.ctx.$router
      }
      if (root.__vue__) {
        const vue = root.__vue__
        return vue.$router || (vue.$root && vue.$root.$router) || (vue.$root && vue.$root.$options && vue.$root.$options.router) || vue._router || null
      }
    } catch { /* */ }
    return null
  }
  function extractRouterBase(router: any): string | null {
    try {
      if (router.options && router.options.base) return router.options.base
      if (router.history && router.history.base) return router.history.base
    } catch { /* */ }
    return null
  }
  function listVueRoutes(router: any): RouteEntry[] {
    const list: RouteEntry[] = []
    try {
      if (typeof router.getRoutes === 'function') {
        router.getRoutes().forEach((r: any) => list.push({ path: r.path || '/', name: r.name || '', meta: safeMeta(r.meta) }))
        if (list.length) return list
      }
      if (router.options && Array.isArray(router.options.routes)) {
        ;(function traverse(routes: any[], base: string): void {
          ;(routes || []).forEach((r: any) => {
            if (!r || typeof r !== 'object') return
            const full = joinPath(base, r.path)
            list.push({ path: full, name: r.name || '', meta: safeMeta(r.meta) })
            if (Array.isArray(r.children) && r.children.length) traverse(r.children, full)
          })
        })(router.options.routes, '')
        if (list.length) return list
      }
      if (router.matcher && typeof router.matcher.getRoutes === 'function') {
        router.matcher.getRoutes().forEach((r: any) => list.push({ path: r.path || '/', name: r.name || '', meta: safeMeta(r.meta) }))
        if (list.length) return list
      }
      if (router.history && router.history.current && Array.isArray(router.history.current.matched)) router.history.current.matched.forEach((r: any) => list.push({ path: r.path || '/', name: r.name || '', meta: safeMeta(r.meta) }))
    } catch { /* */ }
    return list
  }
  function analyzePageLinks(): { detectedBasePath: string; commonPrefixes: Array<{ prefix: string; count: number }> } {
    const result = { detectedBasePath: '', commonPrefixes: [] as Array<{ prefix: string; count: number }> }
    try {
      const links = Array.prototype.slice.call(document.querySelectorAll('a[href]')).map((a: any) => a.getAttribute('href')).filter((h: any) => !!h && h.charAt(0) === '/' && h.indexOf('//') !== 0 && h.indexOf('.') === -1)
      if (links.length < 3) return result
      const counts: Record<string, number> = {}
      links.forEach((l: string) => { const seg = l.split('/').filter(Boolean); if (seg.length) counts[seg[0]] = (counts[seg[0]] || 0) + 1 })
      const sorted = Object.keys(counts).map((k) => ({ prefix: k, count: counts[k] })).sort((a, b) => b.count - a.count)
      result.commonPrefixes = sorted
      if (sorted.length && sorted[0].count / links.length > 0.6) result.detectedBasePath = '/' + sorted[0].prefix
    } catch { /* */ }
    return result
  }

  const r: RouterProbeResult = { framework: null, vueVersion: null, reactVersion: null, reactRouterVersion: null, next: false, routerDetected: false, routerKind: null, allRoutes: [], routerBase: null, perf: [], anchorLinks: [], pageAnalysis: { detectedBasePath: '', commonPrefixes: [] } }
  try { r.perf = (performance as any).getEntriesByType('resource').map((e: any) => ({ name: e.name, initiatorType: e.initiatorType })) } catch { /* */ }
  try { r.anchorLinks = Array.prototype.slice.call(document.querySelectorAll('a[href]')).map((a: any) => a.href) } catch { /* */ }
  try { r.pageAnalysis = analyzePageLinks() } catch { /* */ }

  const vueRoot = findVueRoot()
  if (vueRoot) {
    r.framework = 'vue'
    r.vueVersion = getVueVersion(vueRoot)
    const router = findVueRouter(vueRoot)
    if (router) {
      r.routerDetected = true
      r.routerKind = typeof router.getRoutes === 'function' ? 'Vue Router 4' : 'Vue Router 2/3'
      r.routerBase = extractRouterBase(router)
      r.allRoutes = listVueRoutes(router)
    }
    return r
  }

  // ===== React 只读探测（定位/版本/Fiber 扫描）=====
  function findReactRoot(): any {
    const queue: Array<{ node: any; depth: number }> = [{ node: document.body, depth: 0 }]
    while (queue.length) {
      const it = queue.shift() as { node: any; depth: number }
      if (!it || it.depth > 1000) break
      const el = it.node
      if (el.nodeType === 1) {
        if (findKeyByPrefix(el, '__reactContainer') || el._reactRootContainer || findKeyByPrefix(el, '__reactFiber')) return el
        if (el.childNodes) for (let i = 0; i < el.childNodes.length; i++) queue.push({ node: el.childNodes[i], depth: it.depth + 1 })
      }
    }
    return null
  }
  function getReactRootFiber(el: any): any {
    try {
      const ck = findKeyByPrefix(el, '__reactContainer')
      if (ck) { const c = el[ck]; if (c) return c.current || c }
      if (el._reactRootContainer) {
        const ir = el._reactRootContainer._internalRoot
        if (ir && ir.current) return ir.current
        if (el._reactRootContainer.current) return el._reactRootContainer.current
      }
      const fk = findKeyByPrefix(el, '__reactFiber')
      if (fk) { let f = el[fk]; while (f && f.return) f = f.return; return f }
    } catch { /* */ }
    return null
  }
  function getReactVersion(el: any): string {
    try {
      if ((window as any).React && (window as any).React.version) return (window as any).React.version
      const renderers = (window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ && (window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers
      if (renderers) {
        const keys = Object.keys(renderers)
        for (let i = keys.length - 1; i >= 0; i--) { const ver = renderers[keys[i]] && renderers[keys[i]].version; if (ver) return ver }
      }
    } catch { /* */ }
    if (findKeyByPrefix(el, '__reactContainer')) return '18+ (Concurrent)'
    if (el && el._reactRootContainer) return '≤17 (Legacy)'
    return 'unknown'
  }
  function scanFiber(rootFiber: any, predicate: (o: any) => boolean): any {
    if (!rootFiber) return null
    const queue: any[] = [rootFiber]
    const seen: any[] = []
    let scanned = 0
    function pick(candidates: any[]): any {
      for (const cand of candidates) {
        if (cand && typeof cand === 'object' && predicate(cand)) return cand
        if (cand && typeof cand === 'object' && cand.router && predicate(cand.router)) return cand.router
      }
      return null
    }
    while (queue.length && scanned < 6000) {
      const fiber = queue.shift()
      if (!fiber || typeof fiber !== 'object') continue
      if (seen.indexOf(fiber) !== -1) continue
      seen.push(fiber); scanned++
      const found = pick([fiber.memoizedProps, fiber.stateNode])
      if (found) return found
      let hook = fiber.memoizedState, guard = 0
      while (hook && guard < 100) { const via = pick([hook.memoizedState]); if (via) return via; hook = hook.next; guard++ }
      if (fiber.child) queue.push(fiber.child)
      if (fiber.sibling) queue.push(fiber.sibling)
    }
    return null
  }

  function isReactRouterLike(o: any): boolean {
    return Array.isArray(o.routes) && typeof o.navigate === 'function' && !!(o.state && typeof o.state === 'object')
  }
  function flattenReactRoutes(routes: any[], basePath: string, out: RouteEntry[]): void {
    ;(routes || []).forEach((r0: any) => {
      if (!r0 || typeof r0 !== 'object') return
      const raw = typeof r0.path === 'string' ? r0.path : ''
      let full: string
      if (!raw || r0.index) full = basePath || '/'
      else if (raw.charAt(0) === '/') full = raw
      else full = (basePath === '/' ? '' : basePath || '') + '/' + raw
      if (full.charAt(0) !== '/') full = '/' + full
      full = full.replace(/\/\/+/g, '/')
      out.push({ path: full, name: typeof r0.id === 'string' ? r0.id : r0.name || '', meta: safeMeta(r0.handle) })
      const children = r0.children || r0.routes
      if (Array.isArray(children) && children.length) flattenReactRoutes(children, full, out)
    })
  }
  function isTanStackLike(o: any): boolean {
    return typeof o.navigate === 'function' && !!(o.state && typeof o.state === 'object') && typeof o.state.location === 'object' && !!(o.options && typeof o.options === 'object')
  }
  function collectTanStackRoutes(router: any, out: RouteEntry[]): void {
    try {
      let flat: any[] = []
      if (router.state && Array.isArray(router.state.routes)) flat = router.state.routes
      else if (router.routesById && typeof router.routesById === 'object') flat = Object.keys(router.routesById).map((k) => router.routesById[k])
      else if (router.options && Array.isArray(router.options.routes)) flat = router.options.routes
      flat.forEach((n: any) => {
        if (!n || typeof n !== 'object') return
        let p = n.fullPath || n.path || ''
        if (!p) return
        if (p.charAt(0) !== '/') p = '/' + p
        out.push({ path: p.replace(/\/\/+/g, '/'), name: n.id || '', meta: {} })
      })
    } catch { /* */ }
  }
  function declarativeWalk(rootFiber: any): { routes: RouteEntry[]; mode: string | null } {
    const out: RouteEntry[] = []
    let mode: string | null = null
    const queue: any[] = rootFiber ? [rootFiber] : []
    const seen: any[] = []
    let scanned = 0
    while (queue.length && scanned < 6000) {
      const f = queue.shift()
      if (!f || typeof f !== 'object' || seen.indexOf(f) !== -1) continue
      seen.push(f); scanned++
      const p = f.memoizedProps
      if (p && typeof p === 'object' && typeof p.path === 'string' && ('element' in p || 'component' in p || 'render' in p || 'children' in p)) {
        if (!mode) mode = 'element' in p ? 'v6/v7 声明式' : 'v4/v5 声明式'
        const pp = p.path.charAt(0) === '/' ? p.path : '/' + p.path
        out.push({ path: pp.replace(/\/\/+/g, '/'), name: '', meta: {} })
      }
      if (f.child) queue.push(f.child)
      if (f.sibling) queue.push(f.sibling)
    }
    return { routes: out, mode }
  }
  function collectAnchorRoutes(): RouteEntry[] {
    const out: RouteEntry[] = []
    const seen: Record<string, number> = {}
    try {
      document.querySelectorAll('a[href]').forEach((a: any) => {
        const href = a.getAttribute('href')
        if (!href || href.charAt(0) !== '/' || href.indexOf('//') === 0 || href.indexOf('.') !== -1) return
        const path = href.split('#')[0].split('?')[0]
        if (!path || seen[path]) return
        seen[path] = 1
        out.push({ path, name: '', meta: {} })
      })
    } catch { /* */ }
    return out
  }
  function enumerateNextRoutes(): RouteEntry[] {
    const out: RouteEntry[] = []
    const seen: Record<string, number> = {}
    try {
      const w = window as any
      const router = w.next && w.next.router
      const src = router && (router.components || router.appRouteCache)
      if (src && typeof src === 'object') Object.keys(src).forEach((p) => { if (typeof p === 'string' && p && !seen[p]) { seen[p] = 1; out.push({ path: p.charAt(0) === '/' ? p : '/' + p, name: '', meta: {} }) } })
      const page = w.__NEXT_DATA__ && w.__NEXT_DATA__.page
      if (page && !seen[page]) { seen[page] = 1; out.push({ path: page.charAt(0) === '/' ? page : '/' + page, name: 'next-page', meta: {} }) }
    } catch { /* */ }
    return out
  }

  const reactRoot = findReactRoot()
  if (reactRoot) {
    r.framework = 'react'
    r.reactVersion = getReactVersion(reactRoot)
    const rootFiber = getReactRootFiber(reactRoot)
    const w = window as any
    if (w.next) {
      r.next = true
      r.routerKind = 'Next.js'
      r.reactRouterVersion = (w.next && w.next.version) || '未知版本'
      r.allRoutes = enumerateNextRoutes()
      r.routerDetected = r.allRoutes.length > 0
    } else {
      const dataRouter = scanFiber(rootFiber, isReactRouterLike)
      if (dataRouter) {
        r.routerKind = 'React Router'
        r.reactRouterVersion = dataRouter.future ? 'v7 data router' : 'v6.4+ data router'
        const rr: RouteEntry[] = []
        flattenReactRoutes(dataRouter.routes, '', rr)
        if (!rr.length && dataRouter.state && Array.isArray(dataRouter.state.matches)) dataRouter.state.matches.forEach((m: any) => { if (m && typeof m.pathname === 'string') rr.push({ path: m.pathname, name: m.routeId || '', meta: {} }) })
        r.allRoutes = rr
        r.routerDetected = true
      } else {
        const tanstack = scanFiber(rootFiber, isTanStackLike)
        if (tanstack) {
          r.routerKind = 'TanStack Router'
          r.reactRouterVersion = 'data router'
          const ts: RouteEntry[] = []
          collectTanStackRoutes(tanstack, ts)
          r.allRoutes = ts
          r.routerDetected = true
        } else {
          const dec = declarativeWalk(rootFiber)
          if (dec.routes.length) {
            r.routerKind = 'React Router'
            r.reactRouterVersion = dec.mode
            r.allRoutes = dec.routes
            r.routerDetected = true
          } else {
            r.routerKind = '未知路由库'
            r.allRoutes = collectAnchorRoutes()
            r.routerDetected = false
          }
        }
      }
    }
    try { r.allRoutes.push({ path: (window as any).location.pathname || '/', name: '', meta: {} }) } catch { /* */ }
  }

  return r
}
