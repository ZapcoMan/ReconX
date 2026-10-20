// URL 规范化 + 敏感 URL 三级分类（自 lib/url-classify.js 迁移为 ES 模块）
// normalize：还原常见跳转包装、去跟踪参数与 hash；classify：按特征分 critical/warn/info。
export const TRACKING_PARAMS: string[] = [
  'ved', 'usg', 'ei', 'sa', 'cd', 'rct', 'cad', 'uact', 'aqs', 'sourceid',
  'sxsrf', 'gs_lcp', 'oq', 'gs_lcrp', 'sca_esv', 'sclient',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'spm'
]

export const ENGINE_DOMAINS: string[] = [
  'google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
  'baidu.com', 'bdstatic.com', 'bdimg.com',
  'bing.com', 'bingapis.com', 'microsoft.com', 'msn.com', 'w3.org', 'schema.org'
]

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
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return ''
  }
  const host = u.hostname.toLowerCase()
  if (/google\.[a-z.]+$/.test(host) && u.pathname === '/url') {
    const t = u.searchParams.get('q') || u.searchParams.get('url')
    if (t && /^https?:\/\//i.test(t)) {
      try {
        u = new URL(t)
      } catch {
        return ''
      }
    }
  }
  if (hostMatches(u.hostname.toLowerCase(), 'bing.com') && u.pathname.includes('/ck/a')) {
    const enc = u.searchParams.get('u')
    if (enc) {
      try {
        let d = atob(enc.replace(/^a1/, ''))
        if (!/^https?:\/\//i.test(d)) d = 'https://' + d
        u = new URL(d)
      } catch {
        return ''
      }
    }
  }
  const r = u.searchParams.get('url') || u.searchParams.get('target') || u.searchParams.get('redirectUrl')
  if (r && /^https?:\/\//i.test(r)) {
    try {
      u = new URL(r)
    } catch {
      /* ignore */
    }
  }
  TRACKING_PARAMS.forEach((p) => u.searchParams.delete(p))
  u.hash = ''
  return u.toString()
}

export function isEngineUrl(url: string): boolean {
  let host: string
  try {
    host = new URL(url).hostname.toLowerCase()
  } catch {
    return true
  }
  if (url.indexOf('chrome-extension://') === 0) return true
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
  let host: string
  try {
    host = new URL(url).hostname.toLowerCase()
  } catch {
    return false
  }
  return compiled.domains.some((d) => hostMatches(host, d.domain)) || compiled.regex.some((re) => re.test(url))
}

export interface SensitiveRule {
  id: string
  label: string
  level: string
  re: RegExp
  decode?: boolean
}

export const SENSITIVE_RULES: SensitiveRule[] = [
  { id: 'db', label: '数据库', level: 'critical', re: /\.(sql|db|mdb|dump|sqlite)(\?|$|&)/i },
  { id: 'backup', label: '备份', level: 'critical', re: /(\.bak|\.old|\.zip|\.rar|\.7z|backup|www\.zip|web\.zip|site\.zip)(\?|$|&|\/)/i },
  { id: 'config', label: '配置', level: 'critical', re: /(\.env|config\.php|web\.config|application\.ya?ml|\.ini|\.properties)(\?|$|&)/i },
  { id: 'vcs', label: '版本控制', level: 'critical', re: /(\.git\/|\.svn\/|\.git$|\.svn$)/i },
  { id: 'admin', label: '后台', level: 'warn', re: /(\/admin|\/manage|\/guanli|\/login|\/system)(\/|$|\?)/i },
  { id: 'debug', label: '接口调试', level: 'warn', re: /(swagger|api-docs|druid|actuator|phpinfo|debug|nacos|jenkins)/i },
  { id: 'upload', label: '上传点', level: 'warn', re: /(ueditor|umeditor|uploadify|fileupload|kindeditor)/i },
  { id: 'student', label: '学生数据', level: 'info', re: /(学生|名单|花名册|学籍|录取|成绩|xueji|luqu|chengji)/i, decode: true },
  { id: 'idcard', label: '证件信息', level: 'info', re: /(身份证|证件|idcard|id_card|sfz)/i, decode: true },
  { id: 'doc', label: '文档', level: 'info', re: /\.(xls|xlsx|doc|docx|pdf|csv)(\?|$|&)/i }
]

const WEIGHT: Record<string, number> = { critical: 0, warn: 1, info: 2 }

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
  hits.sort((a, b) => WEIGHT[a.level] - WEIGHT[b.level])
  return { labels: hits.map((h) => h.label), level: hits[0].level }
}

export function rankItems<T extends { url: string }>(items: T[]): Array<T & ClassifyResult> {
  return items
    .map((it) => {
      const c = classify(it.url)
      return Object.assign({}, it, { labels: c.labels, level: c.level })
    })
    .sort((a, b) => (a.level ? WEIGHT[a.level] : 3) - (b.level ? WEIGHT[b.level] : 3))
}
