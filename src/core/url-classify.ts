// URL 规范化 + 敏感 URL 三级分类（自 lib/url-classify.js 迁移为 ES 模块）
// normalize：还原常见跳转包装、去跟踪参数与 hash；classify：按特征分 critical/warn/info。
// URL 解析统一走 url-utils，非法输入不抛错。
import { parseHttpUrl, safeHostname } from './url-utils'

// as const：元组字面量类型，遍历时保留完整字符串信息
export const TRACKING_PARAMS = [
  'ved', 'usg', 'ei', 'sa', 'cd', 'rct', 'cad', 'uact', 'aqs', 'sourceid',
  'sxsrf', 'gs_lcp', 'oq', 'gs_lcrp', 'sca_esv', 'sclient',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'spm'
] as const

export const ENGINE_DOMAINS = [
  'google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
  'baidu.com', 'bdstatic.com', 'bdimg.com',
  'bing.com', 'bingapis.com', 'microsoft.com', 'msn.com', 'w3.org', 'schema.org'
] as const

function safeDecode(v: string): string {
  try {
    return decodeURIComponent(v)
  } catch {
    return v
  }
}
function hostMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain)
}

export function normalize(raw: string): string {
  if (!raw) return ''
  let u = parseHttpUrl(raw)
  if (!u) return ''
  const host = u.hostname.toLowerCase()
  if (/google\.[a-z.]+$/.test(host) && u.pathname === '/url') {
    const t = u.searchParams.get('q') || u.searchParams.get('url')
    if (t && /^https?:\/\//i.test(t)) {
      u = parseHttpUrl(t)
      if (!u) return ''
    }
  }
  if (hostMatches(u.hostname.toLowerCase(), 'bing.com') && u.pathname.includes('/ck/a')) {
    const enc = u.searchParams.get('u')
    if (enc) {
      try {
        let d = atob(enc.replace(/^a1/, ''))
        if (!/^https?:\/\//i.test(d)) d = 'https://' + d
        const next = parseHttpUrl(d)
        if (!next) return ''
        u = next
      } catch {
        return ''
      }
    }
  }
  const r = u.searchParams.get('url') || u.searchParams.get('target') || u.searchParams.get('redirectUrl')
  if (r && /^https?:\/\//i.test(r)) {
    u = parseHttpUrl(r) ?? u
  }
  TRACKING_PARAMS.forEach((p) => u!.searchParams.delete(p))
  u.hash = ''
  return u.toString()
}

export function isEngineUrl(url: string): boolean {
  const host = safeHostname(url)
  if (!host) return true
  if (url.startsWith('chrome-extension://')) return true
  return ENGINE_DOMAINS.some((d) => hostMatches(host, d))
}

export interface CompiledBlacklist {
  regex: RegExp[]
  domains: Array<{ wildcard: boolean; domain: string }>
}

export function compileBlacklist(list: string[] | null | undefined): CompiledBlacklist {
  const regex: RegExp[] = []
  const domains: Array<{ wildcard: boolean; domain: string }> = []
  ;(list || []).forEach((rule) => {
    const v = String(rule).trim()
    if (!v) return
    if (v.length > 2 && v[0] === '/' && v[v.length - 1] === '/') {
      try {
        regex.push(new RegExp(v.slice(1, -1), 'i'))
      } catch {
        /* ignore */
      }
    } else if (v.indexOf('*.') === 0) {
      domains.push({ wildcard: true, domain: v.slice(2).toLowerCase() })
    } else {
      domains.push({ wildcard: false, domain: v.toLowerCase() })
    }
  })
  return { regex, domains }
}

export function matchBlacklist(url: string, compiled: CompiledBlacklist): boolean {
  const host = safeHostname(url)
  if (!host) return false
  return compiled.domains.some((d) => hostMatches(host, d.domain)) || compiled.regex.some((re) => re.test(url))
}

export interface SensitiveRule {
  id: string
  label: string
  /** 分类等级：字面量联合，配合 satisfies 索引时编译期可验 */
  level: 'critical' | 'warn' | 'info'
  re: RegExp
  decode?: boolean
}

// 链接敏感分级规则。
// 与 security-audit 的路径判定同源：URL 是连续字符串，裸词正则会被普通资源名和随机串命中
// （/static/js/debug.js、/assets/sfz1234.png、/api/backup-list 都曾被判成敏感线索）。
// 因此一律要求前导分隔符与后继边界，查询参数形态（?debug=1）单独允许。
export const SENSITIVE_RULES = [
  { id: 'db', label: '数据库', level: 'critical', re: /\.(sql|db|mdb|sqlite|dump)(\?|$|&|\/)/i },
  { id: 'backup', label: '备份', level: 'critical', re: /\.(bak|old)(\?|$|&|\/)|[\/(]backup($|[\/.?])|backup[^?#]*\.(zip|rar|7z|gz|sql|tar\.gz)|(^|[\/.])(www|web|site|beifen)\.(zip|rar|tar\.gz)(\?|$|&)/i },
  { id: 'config', label: '配置', level: 'critical', re: /(\.env|\.ini|\.properties|config\.php|web\.config|application\.ya?ml)(\?|$|&)/i },
  { id: 'vcs', label: '版本控制', level: 'critical', re: /\/\.(git|svn)(\/|$|\?|#)/i },
  // 不含 /login：登录页是预期公开入口，判成"后台 warn"纯属噪音（与路由侧的公开豁免口径一致）
  { id: 'admin', label: '后台', level: 'warn', re: /\/(admin|administrator|manage|manager|management|guanli|console|backend|system)($|[\/.?])/i },
  { id: 'debug', label: '接口调试', level: 'warn', re: /\/(swagger-ui|swagger|api-docs|druid|actuator|phpinfo|nacos|jenkins)($|[\/.?])|[?&](debug|test|trace)=/i },
  { id: 'upload', label: '上传点', level: 'warn', re: /\/(ueditor|umeditor|uploadify|fileupload|kindeditor)(\/|$|\?|\.)/i },
  { id: 'student', label: '学生数据', level: 'info', re: /(学生|名单|花名册|学籍|录取|成绩|xueji|luqu|chengji)/i, decode: true },
  { id: 'idcard', label: '证件信息', level: 'info', re: /(身份证|证件|id[_-]?card|(^|[\/_.])sfz([\/_.]|$))/i, decode: true },
  { id: 'doc', label: '文档', level: 'info', re: /\.(xls|xlsx|doc|docx|pdf|csv)(\?|$|&)/i }
] satisfies SensitiveRule[]

const WEIGHT = { critical: 0, warn: 1, info: 2 } satisfies Record<SensitiveRule['level'], number>

/** 安全取分类权重：字面量键表用 keyof 索引，未知等级排末位 */
const weight = (level: string | null): number => (level && level in WEIGHT ? WEIGHT[level as SensitiveRule['level']] : 3)

export interface ClassifyResult {
  labels: string[]
  level: string | null
}

export function classify(url: string): ClassifyResult {
  const hits: SensitiveRule[] = []
  const decoded = safeDecode(url)
  for (const rule of SENSITIVE_RULES) {
    try {
      const target = rule.decode ? decoded : url
      if (rule.re.test(target)) hits.push(rule)
    } catch {
      /* ignore */
    }
  }
  if (!hits.length) return { labels: [], level: null }
  hits.sort((a, b) => weight(a.level) - weight(b.level))
  return { labels: hits.map((h) => h.label), level: hits[0].level }
}

export function rankItems<T extends { url: string }>(items: T[]): Array<T & ClassifyResult> {
  return items
    .map((it) => {
      const c = classify(it.url)
      return Object.assign({}, it, { labels: c.labels, level: c.level })
    })
    .sort((a, b) => weight(a.level) - weight(b.level))
}
