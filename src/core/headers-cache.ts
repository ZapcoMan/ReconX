/**
 * 响应头缓存（纯逻辑，可注入时钟以便测试）。
 *
 * 由 background 的 webRequest.onHeadersReceived 喂数据，供采集/审计读取。
 * 设计要点（修复原「无范围、无过期、无上限」三问题中的存储层部分）：
 *   - 只缓存「已判定属于允许域」的主机：范围判定由调用方负责，本模块只认 record 进来的主机；
 *   - 每条记录带写入时间，读取时超过 TTL 视为失效并删除，避免陈旧响应头误导审计；
 *   - 主机数超过上限时按更新时间淘汰最旧，杜绝长会话内存无界增长。
 *
 * 时钟通过参数显式传入（now），便于单元测试精确控制过期与淘汰，不依赖真实时间流逝。
 */

export interface HeaderPair { name: string; value: string }
export interface SubFrameHit { type: string; url: string; pairs: HeaderPair[] }
export interface HeadersEntry { main: HeaderPair[]; subFrames: SubFrameHit[]; updatedAt: number }

export const HEADERS_TTL_MS = 30 * 60 * 1000
export const HEADERS_MAX_HOSTS = 200
export const SUB_FRAME_LIMIT = 30

export class HeadersCache {
  private readonly map = new Map<string, HeadersEntry>()
  private readonly ttlMs: number
  private readonly maxHosts: number

  constructor(ttlMs: number = HEADERS_TTL_MS, maxHosts: number = HEADERS_MAX_HOSTS) {
    this.ttlMs = ttlMs
    this.maxHosts = maxHosts
  }

  /**
   * 记录一个主机的响应头。调用方须已确认该主机属于允许域。
   * @param host - 主机名
   * @param frame - 本次响应：type 为 main_frame 时覆盖主文档头，否则追加子帧（带上限）
   * @param now - 当前时间戳（毫秒）
   */
  record(host: string, frame: { type: string; url: string; pairs: HeaderPair[] }, now: number): void {
    const entry = this.map.get(host) ?? { main: [], subFrames: [], updatedAt: 0 }
    if (frame.type === 'main_frame') {
      entry.main = frame.pairs
    } else if (entry.subFrames.length < SUB_FRAME_LIMIT) {
      entry.subFrames.push({ type: frame.type, url: frame.url, pairs: frame.pairs })
    }
    entry.updatedAt = now
    this.map.set(host, entry)
    this.prune()
  }

  /**
   * 读取主机缓存。命中但超过 TTL 的条目视为失效，删除并返回 undefined。
   * @param host - 主机名
   * @param now - 当前时间戳（毫秒）
   */
  read(host: string, now: number): HeadersEntry | undefined {
    const e = this.map.get(host)
    if (!e) return undefined
    if (now - e.updatedAt > this.ttlMs) {
      this.map.delete(host)
      return undefined
    }
    return e
  }

  /** 当前缓存主机数（测试与诊断用） */
  get size(): number {
    return this.map.size
  }

  /** 清空缓存（范围被整体重置时调用） */
  clear(): void {
    this.map.clear()
  }

  private prune(): void {
    if (this.map.size <= this.maxHosts) return
    const ordered = [...this.map.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt)
    const drop = this.map.size - this.maxHosts
    for (let i = 0; i < drop; i++) this.map.delete(ordered[i][0])
  }
}
