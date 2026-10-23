/**
 * 命中置信度分级（纯逻辑，展示/复核层，绝不改动原始命中）。
 *
 * 思路：一条命中"有多可信它是真问题"由几路信号决定——
 *   - 规则本身的严重度基线（critical/high 命中通常比 info 更值得关注）；
 *   - 来源佐证（出现在多个文件 / 多次出现，可信度叠加，有上限避免刷分）；
 *   - 主动探测的响应状态（200 直接暴露最可信，401/403 存在但被守，降级）；
 *   - 误报反馈：被人工标记为误报的，直接判为"存疑"，分数归零。
 *
 * 只产出 score/tier，不移除任何原始命中；计数与展示按 tier 分层即可。
 * 无 chrome / DOM 依赖，纯函数便于回归测试。
 */

export type Tier = 'high' | 'medium' | 'low' | 'suspect'

const SEV_BASE: Record<string, number> = {
  critical: 0.62,
  high: 0.6,
  medium: 0.5,
  low: 0.45,
  info: 0.4
}

/** 严重度/风险等级 → 中文标签（找不到时原样返回，避免吞掉未知值） */
const TIER_CN: Record<Tier, string> = { high: '高', medium: '中', low: '低', suspect: '存疑' }

export function tierOf(score: number): Tier {
  if (score >= 0.75) return 'high'
  if (score >= 0.5) return 'medium'
  if (score >= 0.3) return 'low'
  return 'suspect'
}

export function tierCn(tier: Tier): string {
  return TIER_CN[tier] || tier
}

function round2(n: number): number {
  return Math.round(n * 100) / 100
}

export interface ConfInput {
  /** critical/high/medium/low/info；缺省按 medium 起步 */
  severity?: string
  /** 出现的不同来源文件数（>=1） */
  sourceCount?: number
  /** 命中出现次数（>=1） */
  occurrences?: number
  /** 主动探测的 HTTP 状态码（无则不参与） */
  status?: number
  /** 是否已被人工标记为误报 */
  flagged?: boolean
}

export interface Confidence {
  score: number
  tier: Tier
}

export function confidenceOf(x: ConfInput): Confidence {
  if (x && x.flagged) return { score: 0, tier: 'suspect' }
  let s = SEV_BASE[(x && x.severity) || 'medium']
  if (s === undefined) s = SEV_BASE.medium
  const sc = (x && x.sourceCount) || 1
  if (sc > 1) s += Math.min((sc - 1) * 0.1, 0.2)
  if (((x && x.occurrences) || 1) > 1) s += 0.05
  const st = x && x.status
  if (typeof st === 'number' && st > 0) {
    if (st >= 200 && st < 300) s += 0.2
    else if (st >= 300 && st < 400) s += 0.05
    else if (st === 401 || st === 403) s -= 0.15
  }
  s = Math.max(0, Math.min(1, s))
  return { score: round2(s), tier: tierOf(s) }
}

/** 统计一组 tier 的分布，供摘要展示（高/中/低/存疑 各多少） */
export function tierCounts(tiers: Tier[]): Record<Tier, number> {
  const out: Record<Tier, number> = { high: 0, medium: 0, low: 0, suspect: 0 }
  for (const t of tiers || []) if (t in out) out[t]++
  return out
}
