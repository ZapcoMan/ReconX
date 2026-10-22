// 前端安全审计（自 lib/security-audit.js 迁移为 ES 模块；纯分析，不含任何路由接管能力）
import type { RouteEntry } from '../types'

export interface SensitiveCategory {
  category: string
  keywords: string[]
  riskLevel: string
  description: string
}

// 关键词按"整词匹配"设计（见 matchPathWord），因此每个类别都要把常见派生形写全：
// 只写 auth 就匹配不到 authorization，只写 delete 就匹配不到 deleted。
// 反过来，短词（del / sys / ord）不再靠子串命中长词，/delay、/display 这类路径就不会被误判。
export const SENSITIVE_CATEGORIES: SensitiveCategory[] = [
  // 不收 system/systems：它是泛义词，/api/system-status、/api/system-info 这类状态查询会被判成
  // "管理后台接口 critical"。真正的系统管理端点通常还会被 admin/console/config 等词命中，
  // 收掉它只损失少量重复标注，换来的是状态类端点不再被定成最高危。
  { category: '管理接口', keywords: ['admin', 'admins', 'administrator', 'administrators', 'manage', 'manager', 'management', 'mgr', 'sys', 'superadmin', 'console', 'backend', 'operation'], riskLevel: 'critical', description: '管理后台接口，可能包含敏感操作权限' },
  { category: '删除操作', keywords: ['delete', 'deleted', 'deletion', 'del', 'remove', 'removed', 'destroy', 'drop', 'truncate', 'cancel'], riskLevel: 'critical', description: '数据删除接口，可能导致数据丢失' },
  { category: '修改操作', keywords: ['update', 'updated', 'edit', 'editing', 'modify', 'change', 'changed', 'alter', 'patch', 'put', 'save'], riskLevel: 'high', description: '数据修改接口，可能被用于篡改数据' },
  { category: '认证授权', keywords: ['auth', 'authenticate', 'authentication', 'authorize', 'authorization', 'login', 'signin', 'logout', 'register', 'signup', 'token', 'tokens', 'jwt', 'oauth', 'sso', 'session', 'ticket', 'captcha', 'sms', 'verify'], riskLevel: 'high', description: '认证授权接口，可能被用于暴力破解或越权' },
  { category: '用户数据', keywords: ['user', 'users', 'uid', 'profile', 'account', 'accounts', 'member', 'members', 'customer', 'customers', 'employee', 'employees', 'staff', 'student', 'students', 'teacher'], riskLevel: 'high', description: '用户数据接口，可能泄露个人信息' },
  { category: '支付财务', keywords: ['pay', 'payment', 'payments', 'checkout', 'order', 'orders', 'bill', 'bills', 'billing', 'invoice', 'refund', 'transaction', 'finance', 'money', 'price', 'amount'], riskLevel: 'critical', description: '支付财务接口，涉及资金安全' },
  { category: '文件操作', keywords: ['upload', 'uploads', 'download', 'downloads', 'file', 'files', 'filepath', 'image', 'images', 'avatar', 'attachment', 'attachments', 'export', 'import'], riskLevel: 'medium', description: '文件操作接口，可能被用于文件上传漏洞' },
  { category: '系统配置', keywords: ['config', 'configs', 'configuration', 'setting', 'settings', 'env', 'environment', 'secret', 'secrets', 'key', 'keys', 'password', 'passwd', 'pwd', 'credential', 'credentials'], riskLevel: 'critical', description: '系统配置接口，可能泄露敏感配置信息' },
  { category: '日志审计', keywords: ['log', 'logs', 'audit', 'trace', 'traces', 'history', 'record', 'records', 'stat', 'stats', 'statistics', 'analytics'], riskLevel: 'medium', description: '日志审计接口，可能包含敏感操作记录' },
  { category: '权限角色', keywords: ['role', 'roles', 'perm', 'perms', 'permission', 'permissions', 'privilege', 'privileges', 'authority', 'access'], riskLevel: 'high', description: '权限角色接口，可能被用于提权攻击' },
  { category: '消息通知', keywords: ['notify', 'notification', 'notifications', 'message', 'messages', 'mail', 'emails', 'push', 'alert', 'alerts'], riskLevel: 'low', description: '消息通知接口，可能被用于垃圾信息发送' },
  { category: '搜索查询', keywords: ['search', 'query', 'queries', 'find', 'list', 'lists', 'detail', 'details', 'info', 'fetch', 'retrieve'], riskLevel: 'low', description: '搜索查询接口，可能被用于信息收集' }
]

export interface SensitiveApiHit {
  path: string
  fullUrl: string
  category: string
  matchedKeyword: string
  riskLevel: string
  description: string
  source: string
}

/**
 * 预期就该公开的路径用词。登录、注册、协议、帮助、支付回跳、OAuth 回调这类页面
 * 没有鉴权是正确设计，不该被算成"未授权访问风险"。
 * 判定顺序上公开词优先于敏感词，所以 user-agreement（用户协议）不会被当成用户数据路由。
 */
export const PUBLIC_PATH_WORDS = new Set([
  'login', 'signin', 'sign-in', 'register', 'signup', 'sign-up', 'sso', 'oauth', 'authorize',
  'callback', 'return', 'redirect', 'logout', 'captcha', 'verify-code', 'qrcode',
  'about', 'help', 'faq', 'docs', 'doc', 'guide', 'manual', 'intro', 'news', 'notice',
  'privacy', 'agreement', 'terms', 'consent', 'policy', 'legal', 'copyright',
  '404', '403', '500', '502', '401', 'error', 'notfound', 'blank', 'loading',
  'index', 'home', 'landing', 'root', 'preview', 'share', 'invite', 'download', 'public', 'static', 'assets'
])

/** 把路径切成词：按 / - _ . 空格等非字母数字字符拆分，参数占位符 :id 会被丢掉 */
export function pathTokens(path: string): string[] {
  return String(path || '').toLowerCase().split(/[^a-z0-9]+/).filter((t) => t && t.charAt(0) !== ':')
}

/**
 * 路径关键词匹配。用整词匹配而不是 indexOf 子串匹配——
 * 子串会把 /display 判成支付路由（display 含 pay）、把 /delay 判成删除接口（delay 含 del）、
 * 把 /word 判成订单（word 含 ord 类词）。这类误报在真实站点上非常常见。
 *
 * skipPublic=true 时命中公开用词的路径直接返回 null（不再进入风险统计）。
 * 这个豁免只适用于前端路由：/login、/agreement 这类页面没有鉴权是正确设计。
 * API 端点必须传 false——/api/pay/callback 里含 callback 不代表这个接口不必测，
 * 支付回调恰恰是越权与 IDOR 的高频点，豁免掉就是拿降噪换漏报。
 */
/**
 * 派生形后缀白名单：把整词匹配适度放宽到"词 + 常见英文后缀"，让 users/configs/payment/ordering
 * 仍能命中 user/config/pay/order。
 * 不要用"长度差 ≤N"这种放宽——实测 /api/delay 会因此命中 del（判 critical）、
 * /api/system-status 会命中 stat（判 medium），等于把子串误判换个形式留下。
 */
const WORD_SUFFIXES = new Set(['s', 'es', 'ed', 'ing', 'er', 'ers', 'ion', 'ions', 'ment', 'ments', 'al', 'ly', 'ce', 'ces', 'ge', 'ges', 'd'])

function tokenMatchesWord(token: string, word: string): boolean {
  if (token === word) return true
  if (!token.startsWith(word)) return false
  return WORD_SUFFIXES.has(token.slice(word.length))
}

export function matchPathWord(path: string, words: string[], skipPublic = true): string | null {
  const tokens = pathTokens(path)
  if (!tokens.length) return null
  if (skipPublic) for (const t of tokens) if (PUBLIC_PATH_WORDS.has(t)) return null
  for (const w of words) {
    const lw = w.toLowerCase()
    for (const t of tokens) if (tokenMatchesWord(t, lw)) return w
  }
  return null
}

/**
 * meta 值折算成"是否真的要求鉴权"。
 * 旧实现只看键名存不存在，于是 requiresAuth: false 会被当成"有保护"——
 * 那是把明确声明公开的页面报成安全，属于漏报，比误报更有害。
 */
export function truthyMetaValue(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === '' || v === 0) return false
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase()
    return !(s === 'false' || s === '0' || s === 'no' || s === 'off' || s === 'null' || s === 'undefined')
  }
  if (Array.isArray(v)) return v.length > 0
  if (typeof v === 'object') return Object.keys(v as object).length > 0
  return true
}

export function detectSensitiveApi(path: string, fullUrl: string, source: string): SensitiveApiHit[] {
  const results: SensitiveApiHit[] = []
  for (const cat of SENSITIVE_CATEGORIES) {
    // API 端点不做公开路径豁免（skipPublic=false）：/api/pay/callback 含 callback 也不该放过，
    // 回调与登录类接口正是越权、暴力破解的高频测试点
    const kw = matchPathWord(path, cat.keywords, false)
    if (kw) results.push({ path, fullUrl, category: cat.category, matchedKeyword: kw, riskLevel: cat.riskLevel, description: cat.description, source })
  }
  return results
}

/** 与"未授权访问"关系最密切的几类路径，用于给无鉴权声明的路由定级 */
const PRIVILEGED_CATEGORIES = ['管理接口', '删除操作', '用户数据', '支付财务', '系统配置', '权限角色']

function privilegedCategory(path: string): SensitiveCategory | null {
  for (const cat of SENSITIVE_CATEGORIES) {
    if (PRIVILEGED_CATEGORIES.indexOf(cat.category) < 0) continue
    if (matchPathWord(path, cat.keywords)) return cat
  }
  return null
}

/** 路径是否含公开用词（登录/协议/回跳等），命中即视为预期公开 */
export function isPublicPath(path: string): boolean {
  const tokens = pathTokens(path)
  for (const t of tokens) if (PUBLIC_PATH_WORDS.has(t)) return true
  return false
}

export interface RoutePermissionReport {
  path: string
  name?: string
  hasAuth: boolean
  authKeys: string[]
  hasRoles: boolean
  roles?: string[]
  hasPermissions: boolean
  permissions?: string[]
  isProtected: boolean
  riskLevel: string
  riskDescription: string
}

export function analyzeRoutePermission(route: RouteEntry): RoutePermissionReport {
  const meta = (route.meta || {}) as Record<string, any>
  const authKeys: string[] = []
  let hasRoles = false
  let roles: string[] | undefined
  let hasPermissions = false
  let permissions: string[] | undefined
  for (const kv of Object.entries(meta)) {
    const key = kv[0]
    const value = kv[1]
    const lk = key.toLowerCase()
    if (lk.indexOf('auth') >= 0 || lk === 'requiresauth' || lk === 'needlogin') authKeys.push(key)
    if (lk.indexOf('role') >= 0) {
      hasRoles = true
      roles = Array.isArray(value) ? value.map(String) : typeof value === 'string' ? [value] : roles
    }
    if (lk.indexOf('perm') >= 0) {
      hasPermissions = true
      permissions = Array.isArray(value) ? value.map(String) : typeof value === 'string' ? [value] : permissions
    }
  }
  const hasAuth = authKeys.length > 0
  const isProtected = hasAuth || hasRoles || hasPermissions
  let riskLevel: string, riskDescription: string
  if (!isProtected) {
    const p = (route.path || '').toLowerCase()
    if (p.indexOf('admin') >= 0 || p.indexOf('manage') >= 0 || p.indexOf('sys') >= 0) {
      riskLevel = 'critical'
      riskDescription = '管理相关路由缺少权限保护'
    } else if (p.indexOf('user') >= 0 || p.indexOf('profile') >= 0 || p.indexOf('account') >= 0) {
      riskLevel = 'high'
      riskDescription = '用户相关路由缺少权限保护'
    } else if (p.indexOf('pay') >= 0 || p.indexOf('order') >= 0 || p.indexOf('bill') >= 0) {
      riskLevel = 'critical'
      riskDescription = '支付相关路由缺少权限保护'
    } else {
      riskLevel = 'medium'
      riskDescription = '路由缺少权限保护，可能存在未授权访问（仅为线索，需授权后人工核验）'
    }
  } else if (hasAuth && !hasRoles && !hasPermissions) {
    riskLevel = 'low'
    riskDescription = '仅有基础认证保护，缺少细粒度权限控制'
  } else {
    riskLevel = 'safe'
    riskDescription = '路由权限配置完整'
  }
  return { path: route.path || '', name: route.name, hasAuth, authKeys, hasRoles, roles, hasPermissions, permissions, isProtected, riskLevel, riskDescription }
}

export interface SourceMapRisk {
  mapUrl: string
  scriptUrl: string
  riskLevel: string
  description: string
}

export function analyzeSourceMapRisks(sourceMaps: Array<{ mapUrl: string; scriptUrl: string }> | null | undefined): SourceMapRisk[] {
  // 同样走整词匹配：'key' 用子串会命中 keyboard/turkey，容易把普通模块报成"含敏感配置"。
  // 这里也不做公开词豁免——真实 sourcemap 几乎都挂在 /static/ 或 /assets/ 下，
  // 一旦豁免，/static/js/admin.js.map 这种最该报的反而被放过
  const SENSITIVE_MAP_WORDS = ['admin', 'administrator', 'console', 'backend', 'config', 'configuration', 'settings', 'secret', 'secrets', 'key', 'keys', 'credential', 'credentials', 'env', 'private', 'internal']
  return (sourceMaps || []).map((m) => {
    const hit = matchPathWord(String(m.mapUrl || ''), SENSITIVE_MAP_WORDS, false)
    let riskLevel = 'medium'
    let description = 'Sourcemap 泄露可还原源码'
    if (hit) {
      riskLevel = 'high'
      description = '命中敏感用词「' + hit + '」的模块存在 Sourcemap 泄露，可能暴露关键业务逻辑或配置'
    }
    return { mapUrl: m.mapUrl, scriptUrl: m.scriptUrl, riskLevel, description }
  })
}

export interface AuditParams {
  pageUrl: string
  liveApis?: Array<{ url?: string; path?: string }>
  staticApis?: Array<{ path: string; fullUrl?: string }>
  routes?: RouteEntry[]
  sourceMaps?: Array<{ mapUrl: string; scriptUrl: string }>
}

export function performSecurityAudit(params: AuditParams): Record<string, any> {
  const sensitiveApis: SensitiveApiHit[] = []
  ;(params.liveApis || []).forEach((a) => sensitiveApis.push.apply(sensitiveApis, detectSensitiveApi(a.url || (a as any).path, a.url || (a as any).path, 'live')))
  ;(params.staticApis || []).forEach((a) => sensitiveApis.push.apply(sensitiveApis, detectSensitiveApi(a.path, a.fullUrl || a.path, 'static')))
  const routePermissions = (params.routes || []).map(analyzeRoutePermission)
  const unauthorizedRoutes = routePermissions.filter((r) => !r.isProtected)
  const sourceMapRisks = analyzeSourceMapRisks(params.sourceMaps)

  const criticalCount = sensitiveApis.filter((a) => a.riskLevel === 'critical').length
  const highCount = sensitiveApis.filter((a) => a.riskLevel === 'high').length
  const mediumCount = sensitiveApis.filter((a) => a.riskLevel === 'medium').length
  const lowCount = sensitiveApis.filter((a) => a.riskLevel === 'low').length
  const protectedRoutes = routePermissions.filter((r) => r.isProtected).length
  const unprotectedRoutes = routePermissions.filter((r) => !r.isProtected).length
  let overallRisk: string
  if (criticalCount > 0 || unprotectedRoutes > 5) overallRisk = 'critical'
  else if (highCount > 3 || unprotectedRoutes > 2) overallRisk = 'high'
  else if (mediumCount > 5 || unprotectedRoutes > 0) overallRisk = 'medium'
  else if (lowCount > 0) overallRisk = 'low'
  else overallRisk = 'safe'

  const report: Record<string, any> = {
    timestamp: Date.now(),
    pageUrl: params.pageUrl,
    summary: {
      totalApis: sensitiveApis.length,
      sensitiveApiCount: sensitiveApis.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      totalRoutes: routePermissions.length,
      protectedRoutes,
      unprotectedRoutes,
      sourceMapLeakCount: sourceMapRisks.length,
      overallRisk
    },
    sensitiveApis,
    routePermissions,
    unauthorizedRoutes,
    sourceMapRisks,
    recommendations: []
  }
  const rec: string[] = []
  if (criticalCount > 0) rec.push('发现高危敏感接口，建议检查这些接口的鉴权机制')
  if (unprotectedRoutes > 0) rec.push('发现 ' + unprotectedRoutes + ' 个未受保护的路由（线索），建议授权后人工核验其守卫')
  if (sourceMapRisks.length > 0) rec.push('生产环境不应暴露 Sourcemap，建议构建时禁用或限制访问')
  // 管理路由单独提示也要整词匹配，否则 /commander、/handadmin 之类杂词会把建议写成定论
  if (routePermissions.some((r) => !r.isProtected && matchPathWord(r.path, ['admin', 'administrator', 'superadmin', 'console', 'backend']) !== null)) rec.push('管理路由缺少权限保护，属严重隐患')
  if (sensitiveApis.some((a) => a.source === 'static' && a.riskLevel === 'critical')) rec.push('发现未调用的高危接口，建议重点测试其鉴权')
  if (!rec.length) rec.push('当前未发现明显安全风险，但仍需定期审查')
  report.recommendations = rec
  return report
}
