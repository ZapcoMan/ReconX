// 用户自定义扫描规则：密钥正则与敏感路径探测。JSON 存不了 RegExp，因此自定义条目以
// 正则源码 + flags 落盘，使用时才编译；编译失败或字段不合法就在导入阶段拒绝，
// 绝不让一条坏规则把整次采集带崩。
import { PATTERNS, PATH_PROBES, type PathProbe, type SensitivePattern } from './sensitive-rules'
import type { Severity, UserPattern, UserProbe } from '../types'

export interface ValidationResult { ok: boolean; error?: string; count?: number }

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
/** 正则源码长度上限：够写真实规则，又能挡住明显会在回溯里跑飞的巨型模式 */
export const MAX_PATTERN_SOURCE = 200
export const BUILTIN_PATTERN_COUNT = PATTERNS.length
export const BUILTIN_PROBE_COUNT = PATH_PROBES.length

const isSev = (s: unknown): s is Severity => SEVERITIES.indexOf(s as Severity) >= 0
const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '')

export function compilePattern(u: UserPattern): SensitivePattern | null {
  try {
    const re = new RegExp(u.source, u.flags || 'gi')
    return { id: u.id, name: u.name, severity: u.severity, re, desc: u.desc }
  } catch {
    return null
  }
}

export function validatePatternImport(data: unknown): ValidationResult {
  if (!Array.isArray(data)) return { ok: false, error: '顶层需为数组' }
  for (let i = 0; i < data.length; i++) {
    const d = data[i] as Record<string, unknown>
    if (!d || typeof d !== 'object') return { ok: false, error: `第 ${i + 1} 条不是对象` }
    if (!str(d.id) || !str(d.name)) return { ok: false, error: `第 ${i + 1} 条缺 id 或 name` }
    if (!isSev(d.severity)) return { ok: false, error: `第 ${i + 1} 条 severity 需为 ${SEVERITIES.join('/')}` }
    const src = str(d.source)
    if (!src) return { ok: false, error: `第 ${i + 1} 条缺 source（正则源码，不含 // 包裹）` }
    if (src.length > MAX_PATTERN_SOURCE) return { ok: false, error: `第 ${i + 1} 条 source 超过 ${MAX_PATTERN_SOURCE} 字符` }
    if (!compilePattern(d as unknown as UserPattern)) return { ok: false, error: `第 ${i + 1} 条正则无法编译：${src.slice(0, 40)}` }
  }
  return { ok: true, count: data.length }
}

export function validateProbeImport(data: unknown): ValidationResult {
  if (!Array.isArray(data)) return { ok: false, error: '顶层需为数组' }
  for (let i = 0; i < data.length; i++) {
    const d = data[i] as Record<string, unknown>
    if (!d || typeof d !== 'object') return { ok: false, error: `第 ${i + 1} 条不是对象` }
    const path = str(d.path)
    if (!path.startsWith('/')) return { ok: false, error: `第 ${i + 1} 条 path 需以 / 开头` }
    if (!isSev(d.severity)) return { ok: false, error: `第 ${i + 1} 条 severity 需为 ${SEVERITIES.join('/')}` }
    if (!Array.isArray(d.keywords) || !d.keywords.length) return { ok: false, error: `第 ${i + 1} 条 keywords 需为非空数组` }
  }
  return { ok: true, count: data.length }
}

/** 自定义规则一律追加在内置规则之后：内置规则是漏报底线，不允许被用户条目顶掉 */
export function mergePatterns(builtin: SensitivePattern[], user: UserPattern[] | null | undefined): SensitivePattern[] {
  const taken = new Set(builtin.map((p) => p.id))
  const extra: SensitivePattern[] = []
  for (const u of user || []) {
    if (taken.has(u.id)) continue
    const c = compilePattern(u)
    if (c) { extra.push(c); taken.add(u.id) }
  }
  return builtin.concat(extra)
}

export function mergeProbes(builtin: PathProbe[], user: UserProbe[] | null | undefined): PathProbe[] {
  const taken = new Set(builtin.map((p) => p.path.toLowerCase()))
  const extra: PathProbe[] = []
  for (const u of user || []) {
    const key = str(u.path).toLowerCase()
    if (!key || taken.has(key)) continue
    extra.push({ path: key, method: 'GET', severity: u.severity, keywords: (u.keywords || []).map(String).filter(Boolean), desc: u.desc || '自定义探测' })
    taken.add(key)
  }
  return builtin.concat(extra)
}

/** 备份导出用的可回灌形状（正则还原成源码，去掉 RegExp 实例） */
export function toBackupPatterns(user: UserPattern[] | null | undefined): UserPattern[] {
  return (user || []).map((u) => ({ id: u.id, name: u.name, severity: u.severity, source: u.source, flags: u.flags || 'gi', desc: u.desc || '' }))
}
