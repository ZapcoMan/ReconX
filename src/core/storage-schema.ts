// 存储结构版本化。
// 这个扩展会把结果长期留在用户本机（lastBundle + 最多 20 份历史），一旦结构变更而没有版本号，
// 老用户机器上的数据就无法判断该按哪种形状读——所以版本先于任何结构变更存在。
// 约定：任何新增/改名的存储键与 bundle 字段，都要在此追加一条 Migration，并把 STORAGE_SCHEMA_VERSION 加一。
import { HISTORY_INDEX_KEY, addToIndex, bundleKey, metaOf } from './bundle-store'

/** 存版本号的键 */
export const SCHEMA_KEY = 'schemaVersion'
/** 当前代码期望的存储结构版本 */
export const STORAGE_SCHEMA_VERSION = 1

/** 只用到 get/set/remove 三个方法，便于在测试里注入假存储 */
export interface StorageLike {
  get(keys: string | string[] | null): Promise<Record<string, any>>
  set(items: Record<string, any>): Promise<void>
  remove(keys: string | string[]): Promise<void>
}

export interface Migration {
  from: number
  to: number
  /** 人类可读的迁移说明，日志与断言都用它 */
  label: string
  up: (store: StorageLike) => Promise<void>
}

/**
 * v0 → v1：v0 是没有版本号的早期形态（只有 lastBundle，采集历史靠运行时懒迁移）。
 * 这里把那次懒迁移固化成显式步骤：老数据登记进历史索引，并回写带 id 的 lastBundle，
 * 之后所有读取都能按 id 定位，不再依赖"URL + 时间戳"猜重复。
 */
export const MIGRATIONS: Migration[] = [
  {
    from: 0,
    to: 1,
    label: '把仅有 lastBundle 的旧数据登记进采集历史索引',
    up: async (store) => {
      const d = await store.get(['lastBundle', HISTORY_INDEX_KEY])
      const legacy = d && d.lastBundle
      const index = d && Array.isArray(d[HISTORY_INDEX_KEY]) ? d[HISTORY_INDEX_KEY] : []
      if (!legacy || !legacy.meta || !legacy.meta.collectedAt) return
      const meta = metaOf(legacy)
      // 判重后再写，保证迁移中途失败重跑也不会多出条目
      if (index.some((m: any) => m && m.id === meta.id)) return
      legacy.meta.id = meta.id
      const merged = addToIndex(index, meta)
      await store.set({ [bundleKey(meta.id)]: legacy, [HISTORY_INDEX_KEY]: merged.next, lastBundle: legacy })
    }
  }
]

/** 存储里的版本号可能缺失（老数据）或类型不可靠，统一折算成非负整数 */
export function readVersion(raw: unknown): number {
  const n = typeof raw === 'string' ? Number(raw) : raw
  if (typeof n !== 'number' || !isFinite(n) || n < 0) return 0
  return Math.floor(n)
}

/**
 * 按版本顺序推进迁移。每成功一步立刻落盘版本号，因此中途失败时下一次只会重跑没完成的那一步；
 * 各 up 自身必须幂等。
 */
export async function runMigrations(store: StorageLike, migrations: Migration[] = MIGRATIONS): Promise<{ from: number; to: number; applied: string[] }> {
  const start = readVersion((await store.get(SCHEMA_KEY))[SCHEMA_KEY])
  let v = start
  const applied: string[] = []
  let cursor = 0
  // 按 from 排序后线性推进，避免迁移表书写顺序影响执行顺序
  const ordered = migrations.slice().sort((a, b) => a.from - b.from)
  while (cursor < ordered.length) {
    const m = ordered[cursor]
    if (m.from !== v) { cursor++; continue }
    await m.up(store)
    v = m.to
    applied.push(m.label)
    await store.set({ [SCHEMA_KEY]: v })
    cursor = 0
  }
  return { from: start, to: v, applied }
}
