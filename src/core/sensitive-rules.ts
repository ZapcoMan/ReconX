// JS / 文本 敏感信息扫描规则库（自 lib/sensitive-rules.js 迁移为 ES 模块）
// 命中值明文输出（不再掩码），与 header-checks 的原始头值保持一致，方便取证与复核；导出文件含真实凭据，仅在已授权范围内使用。
import type { Severity } from '../types'

// satisfies：编译期校验键名都属于 Severity，同时保留字面量类型供 keyof 推导
export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } satisfies Partial<Record<Severity, number>>

export interface SensitivePattern {
  id: string
  name: string
  severity: Severity
  re: RegExp
  desc: string
}

export const PATTERNS = [
  { id: 'aws-akid', name: 'AWS Access Key ID', severity: 'high', re: /\b(?:AKIA|ASIA|AIDA|ANPA|ANVA|AROA|AIP|ABIA|ACCA)[0-9A-Z]{16}\b/g, desc: '疑似 AWS 访问密钥 ID' },
  { id: 'aws-secret', name: 'AWS Secret Access Key', severity: 'high', re: /aws.{0,40}(secret|sk).{0,20}['"][0-9A-Za-z/+=]{40}['"]/gi, desc: '疑似 AWS Secret Key' },
  { id: 'gcp-apikey', name: 'Google API Key', severity: 'high', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, desc: 'Google Cloud API Key' },
  { id: 'gcp-oauth', name: 'Google OAuth Client ID', severity: 'medium', re: /\b\d{6,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b/g, desc: 'Google OAuth 客户端 ID' },
  { id: 'gcp-svc-acct', name: 'GCP Service Account', severity: 'critical', re: /"type"\s*:\s*"service_account"/g, desc: 'Google 服务账号 JSON 私钥文件特征' },
  { id: 'github-token', name: 'GitHub Token', severity: 'high', re: /\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{22,})\b/g, desc: 'GitHub PAT / OAuth / 精粒度 token' },
  { id: 'gitlab-token', name: 'GitLab Token', severity: 'high', re: /\bglp[aty]-[0-9A-Za-z_\-]{20,}\b/g, desc: 'GitLab PAT/Runner/Trigger token' },
  { id: 'slack-token', name: 'Slack Token', severity: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, desc: 'Slack xox 令牌' },
  { id: 'slack-webhook', name: 'Slack Webhook', severity: 'high', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]+\/B[0-9A-Za-z_]+\/[0-9A-Za-z]+/g, desc: 'Slack Incoming Webhook' },
  { id: 'discord-webhook', name: 'Discord Webhook', severity: 'high', re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g, desc: 'Discord Webhook URL' },
  { id: 'discord-token', name: 'Discord Bot Token', severity: 'high', re: /\b[MN][0-9A-Za-z]{23,25}\.[0-9A-Za-z_\-]{6}\.[0-9A-Za-z_\-]{27,40}\b/g, desc: 'Discord 机器人令牌' },
  { id: 'stripe', name: 'Stripe Key', severity: 'high', re: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b/g, desc: 'Stripe secret/restricted key（live 为高危）' },
  { id: 'twilio-key', name: 'Twilio Credential', severity: 'high', re: /\b(?:AC[0-9a-f]{32}|SK[0-9a-f]{32})\b/g, desc: 'Twilio Account SID / API Key SID' },
  { id: 'private-key', name: 'Private Key Block', severity: 'critical', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, desc: 'PEM 私钥块' },
  { id: 'ssh-key', name: 'SSH Private Key', severity: 'critical', re: /-----BEGIN OPENSSH PRIVATE KEY-----/g, desc: 'OpenSSH 私钥' },
  { id: 'jwt', name: 'JWT', severity: 'medium', re: /\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b/g, desc: 'JSON Web Token（可解码查看 claims/签发者）' },
  { id: 'openai-key', name: 'OpenAI Key', severity: 'high', re: /\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b/g, desc: 'OpenAI API Key' },
  { id: 'anthropic-key', name: 'Anthropic Key', severity: 'high', re: /\bsk-ant-[0-9A-Za-z_\-]{20,}\b/g, desc: 'Anthropic API Key' },
  { id: 'sendgrid-key', name: 'SendGrid Key', severity: 'high', re: /\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}\b/g, desc: 'SendGrid API Key' },
  { id: 'npm-token', name: 'npm Token', severity: 'high', re: /\bnpm_[0-9A-Za-z]{36}\b/g, desc: 'npm 访问令牌' },
  { id: 'docker-token', name: 'Docker PAT', severity: 'high', re: /\bdckr_pat_[0-9A-Za-z_\-]{20,}\b/g, desc: 'Docker 个人访问令牌' },
  { id: 'telegram-bot', name: 'Telegram Bot Token', severity: 'high', re: /\b\d{8,10}:AA[0-9A-Za-z_\-]{30,}\b/g, desc: 'Telegram 机器人令牌' },
  { id: 'mapbox-token', name: 'Mapbox Token', severity: 'medium', re: /\b(?:pk|sk)\.eyJ[0-9A-Za-z_.\-]{40,}\b/g, desc: 'Mapbox 令牌' },
  { id: 'azure-storage', name: 'Azure Storage Connection', severity: 'high', re: /AccountName=[0-9a-z]+;AccountKey=[A-Za-z0-9+/=]{40,}/g, desc: 'Azure 存储连接串（含 AccountKey）' },
  { id: 'facebook-token', name: 'Facebook Access Token', severity: 'medium', re: /\bEAA[0-9A-Za-z]{50,}\b/g, desc: 'Facebook Graph API 令牌' },
  { id: 'basic-auth-url', name: 'URL 内嵌凭据', severity: 'high', re: /\bhttps?:\/\/[^\s/]+:[^\s@/]+@[^\s/]+/g, desc: 'user:pass@host 形式的内嵌认证 URL' },
  { id: 'generic-secret', name: '通用密钥/令牌赋值', severity: 'medium', re: /\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)\b['"`]?\s*[:=]\s*['"`][^'"`\s]{12,}['"`]/gi, desc: '疑似硬编码密钥/令牌' },
  { id: 'password-assign', name: '疑似口令赋值', severity: 'low', re: /\b(?:password|passwd|pwd)\b['"`]?\s*[:=]\s*['"`][^'"`\s]{4,}['"`]/gi, desc: '硬编码口令（噪声较高，需人工判断）' },
  { id: 'internal-host', name: '内网/元数据地址泄露', severity: 'medium', re: /\b(?:https?:\/\/)?(?:localhost|127(?:\.[0-9]{1,3}){3}|10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|169\.254\.169\.254|metadata\.google\.internal|169\.254\.[0-9]+\.[0-9]+|[a-z0-9-]+\.local\b|(?:internal|intranet|corp)\.[a-z0-9.-]+)/gi, desc: '前端 JS 暴露内网/云元数据端点，是 SSRF/拓扑线索' },
  { id: 'sourcemap', name: 'Source Map 暴露', severity: 'low', re: /[#@]sourceMappingURL=([^\s'"]+)/g, desc: '存在 source map，可还原原始源码' },
  { id: 'git-ref', name: 'Git 仓库痕迹', severity: 'low', re: /(git@[\w.-]+:[\w./-]+|\.git\/(?:HEAD|config))/gi, desc: '源码里残留 Git 仓库地址/路径' },
  { id: 'pii-email', name: '邮箱（潜在 PII）', severity: 'info', re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, desc: '出现邮箱，可能是开发者/用户 PII' },
  { id: 'phone-cn', name: '手机号（潜在 PII）', severity: 'info', re: /\b1[3-9]\d{9}\b/g, desc: '出现疑似中国大陆手机号' }
] satisfies SensitivePattern[]

export interface PathProbe {
  path: string
  method: string
  severity: Severity
  keywords: string[]
  desc: string
}

export const PATH_PROBES = [
  { path: '/.git/HEAD', method: 'GET', severity: 'high', keywords: ['ref:'], desc: 'Git 仓库可读取（源码泄露）' },
  { path: '/.git/config', method: 'GET', severity: 'high', keywords: ['[core]', '[remote'], desc: 'Git config 暴露' },
  { path: '/.env', method: 'GET', severity: 'high', keywords: ['=', 'app_key', 'db_', 'secret'], desc: '.env 配置泄露' },
  { path: '/.env.production', method: 'GET', severity: 'high', keywords: ['=', 'db_'], desc: '生产环境 .env' },
  { path: '/.svn/entries', method: 'GET', severity: 'medium', keywords: ['dir'], desc: 'SVN 元数据' },
  { path: '/.DS_Store', method: 'GET', severity: 'low', keywords: ['bud1'], desc: '目录结构泄露' },
  { path: '/web.config', method: 'GET', severity: 'medium', keywords: ['<?xml', 'configuration'], desc: 'IIS 配置泄露' },
  { path: '/.aws/credentials', method: 'GET', severity: 'high', keywords: ['aws_access_key_id'], desc: 'AWS 凭据泄露' },
  { path: '/phpinfo.php', method: 'GET', severity: 'medium', keywords: ['phpinfo()', 'php version'], desc: 'phpinfo 暴露' },
  { path: '/server-status', method: 'GET', severity: 'medium', keywords: ['apache server status'], desc: 'Apache 状态页' },
  { path: '/server-info', method: 'GET', severity: 'medium', keywords: ['server information'], desc: 'Apache 信息页' },
  { path: '/actuator/env', method: 'GET', severity: 'high', keywords: ['property', 'source'], desc: 'Spring Actuator 环境端点' },
  { path: '/actuator', method: 'GET', severity: 'medium', keywords: ['_links', 'beans', 'health'], desc: 'Spring Actuator 暴露' },
  { path: '/api/swagger.json', method: 'GET', severity: 'medium', keywords: ['openapi', 'swagger'], desc: 'Swagger/OpenAPI 文档暴露' },
  { path: '/openapi.json', method: 'GET', severity: 'medium', keywords: ['openapi', 'paths'], desc: 'OpenAPI 规范暴露' },
  { path: '/.well-known/security.txt', method: 'GET', severity: 'info', keywords: ['contact:', 'expires:'], desc: '安全联系人（赏金/披露渠道，正向发现）' },
  { path: '/composer.json', method: 'GET', severity: 'low', keywords: ['require', 'name'], desc: '依赖清单泄露（技术栈+版本线索）' },
  { path: '/package.json', method: 'GET', severity: 'low', keywords: ['dependencies', 'name'], desc: '依赖清单泄露（技术栈+版本线索）' },
  { path: '/.hidden', method: 'GET', severity: 'info', keywords: ['admin', 'api', 'staging', 'internal', 'backup', 'test', 'debug'], desc: '隐藏管理员 API（HIDDEN-MGMT 模式）' }
] satisfies PathProbe[]

export function decodeJwt(token: string): Record<string, any> {
  try {
    const parts = String(token).split('.')
    if (parts.length < 2) return { error: 'format' }
    const b64url = (s: string): string => {
      s = s.replace(/-/g, '+').replace(/_/g, '/')
      while (s.length % 4) s += '='
      return decodeURIComponent(
        atob(s)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      )
    }
    const header = JSON.parse(b64url(parts[0]))
    const payload = JSON.parse(b64url(parts[1]))
    return { header, payload }
  } catch (e: any) {
    return { error: String((e && e.message) || e) }
  }
}

export interface FindingSample {
  /** 命中原文（明文，不再掩码） */
  value: string
  at: number
}
export interface Finding {
  id: string
  name: string
  severity: Severity
  desc: string
  url?: string
  count: number
  samples: FindingSample[]
  jwtDecoded?: Record<string, any>
}

export function scanText(text: string, url?: string, opts?: { perRuleCap?: number; extraPatterns?: SensitivePattern[] }): Finding[] {
  opts = opts || {}
  const perRuleCap = opts.perRuleCap || 8
  const findings: Finding[] = []
  const body = String(text || '')
  // PATTERNS 用 satisfies 保留了字面量 severity 类型，与用户规则并扫时统一按接口类型遍历
  const rules: SensitivePattern[] = [...PATTERNS, ...(opts.extraPatterns || [])]
  for (const p of rules) {
    const re = new RegExp(p.re.source, p.re.flags)
    const samples: FindingSample[] = []
    let m: RegExpExecArray | null
    let guard = 0
    while ((m = re.exec(body)) !== null && guard < 5000) {
      guard++
      if (m[0].length === 0) {
        re.lastIndex++
        continue
      }
      samples.push({ value: m[1] || m[0], at: m.index })
      if (samples.length >= perRuleCap) break
    }
    if (samples.length) {
      const f: Finding = { id: p.id, name: p.name, severity: p.severity, desc: p.desc, url, count: samples.length, samples }
      if (p.id === 'jwt' && samples.length) {
        const r2 = new RegExp(p.re.source, p.re.flags)
        const mm = r2.exec(body)
        if (mm) f.jwtDecoded = decodeJwt(mm[0])
      }
      findings.push(f)
    }
  }
  return findings
}

// 风险等级中文标签：satisfies 保证键名合法，查不到时回退原串
const RISK_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' } satisfies Partial<Record<Severity, string>>

export function riskLabel(sevLevel: string): string {
  return RISK_CN[sevLevel as keyof typeof RISK_CN] ?? sevLevel
}
