/**
 * 误报反馈闭环的纯逻辑（展示/复核层，绝不改动原始命中）。
 *
 * 设计原则：
 *   - 标记只影响"展示与风险计数"，原始 bundle 命中一律保留（取证完整性优先）；
 *   - 默认按「站点 + 签名」维度记录（site），A 站的误报标记不会让 B 站的同类真漏洞被藏掉；
 *     仅当用户显式选 global 时才跨站生效；
 *   - 存储为 mapKey 字符串集合（chrome.storage.local 的 falsePositives 键），可逐条撤销。
 *
 * 时钟/存储都不参与本模块，纯函数便于回归测试。
 */

export type FpKind = 'finding' | 'probe' | 'api' | 'route'

/** 命中签名：kind + 稳定 key（规则 id / 路径）。同 kind 同 key 视为同一误报目标 */
export function fpSignature(kind: FpKind, key: string): string {
  return kind + ':' + String(key == null ? '' : key)
}

/** 存储键：site 维度带 host，global 维度用 '*' 前缀 */
export function fpMapKey(host: string, sig: string, scope: 'site' | 'global' = 'site'): string {
  return (scope === 'global' ? '*' : String(host || '')) + '|' + sig
}

/** 解析存储键供设置页可读展示 */
export function describeFp(mapKey: string): { scope: 'site' | 'global'; host: string; kind: string; key: string } {
  const i = mapKey.indexOf('|')
  const head = i < 0 ? '' : mapKey.slice(0, i)
  const sig = i < 0 ? mapKey : mapKey.slice(i + 1)
  const c = sig.indexOf(':')
  return {
    scope: head === '*' ? 'global' : 'site',
    host: head === '*' ? '（全站）' : (head || '（未知站点）'),
    kind: c < 0 ? sig : sig.slice(0, c),
    key: c < 0 ? '' : sig.slice(c + 1)
  }
}

/** 列表 → 去重 Set（忽略空串） */
export function fpSet(list: string[] | null | undefined): Set<string> {
  const s = new Set<string>()
  for (const k of list || []) if (typeof k === 'string' && k) s.add(k)
  return s
}

/**
 * 按误报集合把命中列表拆成 kept（未标记）/ ignored（已标记）。
 * @param sigOf 从条目算签名的函数（由调用方按 kind 提供）
 */
export function splitByFp<T>(items: T[] | null | undefined, host: string, set: Set<string>, sigOf: (item: T) => string): { kept: T[]; ignored: T[] } {
  const kept: T[] = []
  const ignored: T[] = []
  for (const it of items || []) {
    const sig = sigOf(it)
    if (set.has(fpMapKey(host, sig, 'site')) || set.has(fpMapKey('*', sig, 'global'))) ignored.push(it)
    else kept.push(it)
  }
  return { kept, ignored }
}

/** 在列表里增删一个 mapKey，返回新数组（幂等：重复添加不产生重复项） */
export function withFp(list: string[], mapKey: string): string[] {
  if (!mapKey || list.indexOf(mapKey) >= 0) return list.slice()
  return list.concat([mapKey])
}
export function withoutFp(list: string[], mapKey: string): string[] {
  return list.filter((k) => k !== mapKey)
}
