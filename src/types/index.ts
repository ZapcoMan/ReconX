// ReconX 跨模块共享类型（编译期存在，无运行时输出）

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warn' | 'safe'

export interface HeaderPair {
  name: string
  value: string
}

// 指纹规则：正则 + 名称（可选版本标记）
export interface PatternRule {
  re: RegExp
  name: string
  version?: string
}

export interface GlobalVarProbe {
  probe: string
  name: string
  versionPaths?: string[]
  weak?: boolean
}

export interface WindowVarHit {
  name: string
  probe: string
  weak: boolean
  version: string | null
}

export interface WafHeaderSpec {
  n: string
  v?: RegExp
}
export interface WafRule {
  name: string
  vendor?: string
  headers?: WafHeaderSpec[]
  cookies?: RegExp[]
  html?: RegExp[]
  note?: string
}

// 归一化路由条目
export interface RouteEntry {
  path?: string
  name?: string
  meta?: Record<string, unknown>
}

// 只读框架/路由探测结果（router-probe 注入回传；字段契约与 collect-extras/tech-stack 对齐）
export interface RouterProbeResult {
  framework: 'vue' | 'react' | null
  vueVersion: string | null
  reactVersion: string | null
  reactRouterVersion: string | null
  next: boolean
  routerDetected: boolean
  routerKind: string | null
  allRoutes: RouteEntry[]
  routerBase: string | null
  perf: Array<{ name: string; initiatorType: string }>
  anchorLinks: string[]
  pageAnalysis?: { detectedBasePath: string; commonPrefixes: Array<{ prefix: string; count: number }> }
  error?: string
}

export interface ScopeHost {
  host: string
  origin: string
  addedAt: number
  note: string
}
export interface Scope {
  hosts: ScopeHost[]
}

/** 自定义密钥正则：JSON 存不了 RegExp，故落盘源码 + flags，用时才编译 */
export interface UserPattern {
  id: string
  name: string
  severity: Severity
  source: string
  flags?: string
  desc: string
}
/** 自定义敏感路径探测条目 */
export interface UserProbe {
  path: string
  severity: Severity
  keywords: string[]
  desc: string
}

export interface Settings {
  activeProbe: boolean
  maxJsFiles: number
  maxConcurrent: number
  theme: 'dark' | 'light' | 'geek'
  /** 链接采集黑名单：裸域 / *.通配域 / 正则 /re/ 三种写法，解析见 url-classify.compileBlacklist */
  linkBlacklist: string[]
  /** 自定义密钥正则（正则源码 + flags），编译与校验见 core/user-rules */
  userPatterns: UserPattern[]
  /** 自定义敏感路径探测条目 */
  userProbes: UserProbe[]
}

export interface TechItem {
  name: string
  category: string
  version: string | null
  confidence: number
  evidence: string[]
}

export interface TechStackResult {
  items: TechItem[]
  framework: {
    vue: boolean
    react: boolean
    spa: boolean
    routerDetected: boolean
    routerKind: string | null
    vueVersion: string | null
    reactVersion: string | null
    next: boolean
  }
  decision: { enableRouteProbe: boolean; reason: string }
}

// 采集结果 bundle：结构动态，按段类型化主要字段，其余以宽松类型兜底
export interface ReconBundle {
  meta: Record<string, any>
  links: Record<string, any>
  resources: Record<string, any>
  tech: TechItem[]
  waf: Array<Record<string, any>>
  headers: Record<string, any>
  js: Record<string, any>
  probes: Record<string, any>
  risks: Array<Record<string, any>>
  routes?: Record<string, any>
  api?: Record<string, any>
  security?: Record<string, any>
  techStack?: TechStackResult
}
