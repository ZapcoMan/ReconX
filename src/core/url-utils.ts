// URL 工具库：全项目统一的安全解析 / 主机与来源提取 / 路径拼接 / 文件名提取。
// 任何模块需要处理 URL 都从这里走，避免各处散落 new URL + try/catch 与字符串手拼。
// 类型说明：HttpUrl 用模板字面量类型约束“必须带 http(s) 前缀”的字符串，入口处即可拦截脏数据。

/** 以 http(s) 开头的 URL 字符串 */
export type HttpUrl = `${'http' | 'https'}://${string}`

/** 仅接受 http/https URL；解析失败返回 null（绝不抛错），base 可传相对基准 */
export function parseHttpUrl(url: string | null | undefined, base?: string): URL | null {
  if (!url) return null
  try {
    const u = new URL(String(url), base)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return u
  } catch {
    return null
  }
}

/** 是否为可解析的 http/https URL（给了 base 时允许相对地址） */
export function isHttpUrl(url: string | null | undefined, base?: string): boolean {
  return parseHttpUrl(url, base) !== null
}

/** 主机名（小写）；非法输入返回空串，调用方统一 if (!host) 判断 */
export function safeHostname(url: string | null | undefined, base?: string): string {
  return parseHttpUrl(url, base)?.hostname.toLowerCase() ?? ''
}

/** URL 的 origin；非法返回空串 */
export function originOf(url: string | null | undefined): string {
  return parseHttpUrl(url)?.origin ?? ''
}

/** 相对 base 解析出绝对 URL；仅 http/https，失败返回 null */
export function toAbsolute(href: string | null | undefined, base: string): URL | null {
  return parseHttpUrl(href, base)
}

/** 资源文件名：路径最后一段（自动去查询串与 hash）；无路径时退回主机名；非法 URL 退回去参原串 */
export function filenameOf(url: string): string {
  const u = parseHttpUrl(url)
  if (!u) return String(url).split('?')[0].split('#')[0]
  return u.pathname.split('/').filter(Boolean).at(-1) ?? u.hostname
}

/** 路径段折叠重复斜杠并去尾斜杠（与 route-urls 的历史 cleanUrl 语义一致） */
export function cleanPathSlash(s: string): string {
  return String(s || '').replace(/([^:]\/)\/+/g, '$1').replace(/\/$/, '')
}

/** origin/base 与 path 的安全拼接：折叠重复斜杠、保证 path 前置 /；path 为空时只返回去尾斜杠的 base */
export function joinPath(originOrBase: string, path: string): string {
  const base = String(originOrBase || '').replace(/\/+$/, '')
  const p = String(path || '')
  if (!p) return base
  return cleanPathSlash(base + (p.startsWith('/') ? p : '/' + p))
}

/** 接管/回传场景的站点标识键：小写 hostname；非 http(s) 返回空串 */
export function getAllInSiteKey(url: string | undefined): string {
  return safeHostname(url)
}
