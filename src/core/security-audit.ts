// 前端安全审计（自 lib/security-audit.js 迁移为 ES 模块；纯分析，不含任何路由接管能力）
import type { RouteEntry } from '../types'

export interface SensitiveCategory {
  category: string
  keywords: string[]
  riskLevel: string
  description: string
}

export const SENSITIVE_CATEGORIES: SensitiveCategory[] = [
  { category: '管理接口', keywords: ['admin', 'manager', 'mgr', 'sys', 'system', 'manage', 'superadmin', 'administrator'], riskLevel: 'critical', description: '管理后台接口，可能包含敏感操作权限' },
  { category: '删除操作', keywords: ['delete', 'del', 'remove', 'destroy', 'drop', 'truncate'], riskLevel: 'critical', description: '数据删除接口，可能导致数据丢失' },
  { category: '修改操作', keywords: ['update', 'edit', 'modify', 'change', 'alter', 'patch', 'put'], riskLevel: 'high', description: '数据修改接口，可能被用于篡改数据' },
  { category: '认证授权', keywords: ['auth', 'login', 'logout', 'register', 'signup', 'signin', 'token', 'oauth', 'sso', 'captcha', 'sms', 'verify'], riskLevel: 'high', description: '认证授权接口，可能被用于暴力破解或越权' },
  { category: '用户数据', keywords: ['user', 'users', 'profile', 'account', 'member', 'customer', 'employee', 'staff'], riskLevel: 'high', description: '用户数据接口，可能泄露个人信息' },
  { category: '支付财务', keywords: ['pay', 'payment', 'order', 'bill', 'invoice', 'refund', 'transaction', 'finance', 'money', 'price', 'cost'], riskLevel: 'critical', description: '支付财务接口，涉及资金安全' },
  { category: '文件操作', keywords: ['upload', 'download', 'file', 'files', 'image', 'images', 'avatar', 'attachment', 'export', 'import'], riskLevel: 'medium', description: '文件操作接口，可能被用于文件上传漏洞' },
  { category: '系统配置', keywords: ['config', 'setting', 'settings', 'env', 'environment', 'secret', 'key', 'password', 'pwd'], riskLevel: 'critical', description: '系统配置接口，可能泄露敏感配置信息' },
  { category: '日志审计', keywords: ['log', 'logs', 'audit', 'trace', 'history', 'record', 'stat', 'stats', 'analytics'], riskLevel: 'medium', description: '日志审计接口，可能包含敏感操作记录' },
  { category: '权限角色', keywords: ['role', 'roles', 'perm', 'permission', 'permissions', 'access', 'privilege', 'authority'], riskLevel: 'high', description: '权限角色接口，可能被用于提权攻击' },
  { category: '消息通知', keywords: ['notify', 'notification', 'message', 'mail', 'email', 'push', 'alert'], riskLevel: 'low', description: '消息通知接口，可能被用于垃圾信息发送' },
  { category: '搜索查询', keywords: ['search', 'query', 'find', 'list', 'detail', 'info', 'get', 'fetch', 'retrieve'], riskLevel: 'low', description: '搜索查询接口，可能被用于信息收集' }
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

export function detectSensitiveApi(path: string, fullUrl: string, source: string): SensitiveApiHit[] {
  const results: SensitiveApiHit[] = []
  const lower = String(path || '').toLowerCase()
  for (const cat of SENSITIVE_CATEGORIES) {
    for (const kw of cat.keywords) {
      if (lower.indexOf(kw) >= 0) {
        results.push({ path, fullUrl, category: cat.category, matchedKeyword: kw, riskLevel: cat.riskLevel, description: cat.description, source })
        break
      }
    }
  }
  return results
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
  return (sourceMaps || []).map((m) => {
    const l = String(m.mapUrl || '').toLowerCase()
    let riskLevel = 'medium'
    let description = 'Sourcemap 泄露可还原源码'
    if (l.indexOf('admin') >= 0 || l.indexOf('config') >= 0 || l.indexOf('secret') >= 0) {
      riskLevel = 'high'
      description = '敏感模块的 Sourcemap 泄露，可能暴露关键业务逻辑'
    }
    if (l.indexOf('.env') >= 0 || l.indexOf('secret') >= 0 || l.indexOf('key') >= 0) {
      riskLevel = 'high'
      description = '可能包含敏感配置信息的 Sourcemap 泄露'
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
  if (routePermissions.some((r) => r.path.toLowerCase().indexOf('admin') >= 0 && !r.isProtected)) rec.push('管理路由缺少权限保护，属严重隐患')
  if (sensitiveApis.some((a) => a.source === 'static' && a.riskLevel === 'critical')) rec.push('发现未调用的高危接口，建议重点测试其鉴权')
  if (!rec.length) rec.push('当前未发现明显安全风险，但仍需定期审查')
  report.recommendations = rec
  return report
}
