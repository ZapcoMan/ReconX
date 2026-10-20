// 资产测绘查询生成（自 lib/asset-search.js 迁移为 ES 模块；仅生成查询 URL，不自动开标签）
export function utf8Base64(input: string): string {
  const bytes = new TextEncoder().encode(input)
  let binary = ''
  bytes.forEach((b) => {
    binary += String.fromCharCode(b)
  })
  return btoa(binary)
}
function fp(t: { keyword?: string }): string {
  return (t.keyword || '').trim()
}
export interface AssetTarget {
  domain: string
  keyword?: string
}
export interface AssetPlatform {
  id: string
  name: string
  tip: string
  query: Record<string, (t: AssetTarget) => string>
  url: (q: string) => string
}
export const PLATFORMS: AssetPlatform[] = [
  {
    id: 'fofa', name: 'Fofa', tip: '免费账号有查询条数限制',
    query: { domain: (t) => `domain="${t.domain}"`, cert: (t) => `cert="${t.domain}"`, fingerprint: (t) => `domain="${t.domain}" && (title="${fp(t)}" || body="${fp(t)}")`, icp: (t) => `icp="${fp(t)}"` },
    url: (q) => `https://fofa.info/result?qbase64=${encodeURIComponent(utf8Base64(q))}`
  },
  {
    id: 'quake', name: '360 Quake', tip: '需登录；不支持按备案主体检索',
    query: { domain: (t) => `domain:"${t.domain}"`, cert: (t) => `cert:"${t.domain}"`, fingerprint: (t) => `domain:"${t.domain}" && (title:"${fp(t)}" || app:"${fp(t)}")` },
    url: (q) => `https://quake.360.net/quake/#/searchResult?searchVal=${encodeURIComponent(q)}`
  },
  {
    id: 'hunter', name: '鹰图 Hunter', tip: '需登录且消耗积分',
    query: { domain: (t) => `domain.suffix="${t.domain}"`, cert: (t) => `cert="${t.domain}"`, fingerprint: (t) => `domain.suffix="${t.domain}" && (web.title="${fp(t)}" || web.body="${fp(t)}")` },
    url: (q) => `https://hunter.qianxin.com/home/dataSearch?searchValue=${encodeURIComponent(q)}`
  },
  {
    id: 'zoomeye', name: 'ZoomEye', tip: '免费账号每日查询次数有限',
    query: { domain: (t) => `site:"${t.domain}"`, cert: (t) => `ssl:"${t.domain}"`, fingerprint: (t) => `site:"${t.domain}" && (title:"${fp(t)}" || app:"${fp(t)}")`, icp: (t) => `icp="${fp(t)}"` },
    url: (q) => `https://www.zoomeye.org/searchResult?q=${encodeURIComponent(q)}`
  }
]
export interface AssetMode {
  id: string
  name: string
  hint: string
  needsKeyword: boolean
}
export const ASSET_MODES: AssetMode[] = [
  { id: 'domain', name: '主域', hint: '查询该域名下的全部资产', needsKeyword: false },
  { id: 'cert', name: '证书拓线', hint: '查同一张 TLS 证书下的旁站与隐藏域名', needsKeyword: false },
  { id: 'fingerprint', name: '组件指纹', hint: '关键词填组件名，如 Nacos / Druid / 泛微', needsKeyword: true },
  { id: 'icp', name: '备案主体', hint: '关键词填单位名称，如 某某大学', needsKeyword: true }
]
export interface ExtraSource {
  id: string
  name: string
  hint: string
  build: (d: string) => string
}
export const EXTRA_SOURCES: ExtraSource[] = [
  { id: 'crtname', name: 'crt.name', hint: '证书透明日志枚举子域名（国内直连）', build: (d) => `https://crt.name/v1/search?apex=${encodeURIComponent(d)}` },
  { id: 'wayback', name: 'Wayback', hint: '历史快照，找回已下线老系统', build: (d) => `https://web.archive.org/web/*/${encodeURIComponent(d)}/*` },
  { id: 'virustotal', name: 'VirusTotal', hint: '子域与解析记录', build: (d) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(d)}/relations` },
  { id: 'shodan', name: 'Shodan', hint: '海外资产与开放服务', build: (d) => `https://www.shodan.io/search?query=${encodeURIComponent(d)}` },
  { id: 'aiqicha', name: '爱企查', hint: '查主办单位与关联域名', build: (d) => `https://aiqicha.baidu.com/s?q=${encodeURIComponent(d)}` },
  { id: 'beian', name: 'ICP 备案', hint: '工信部备案查询', build: () => 'https://beian.miit.gov.cn/#/Integrated/recordQuery' }
]
export const getPlatform = (id: string): AssetPlatform | undefined => PLATFORMS.find((p) => p.id === id)
export const supportsMode = (platform: AssetPlatform, mode: string): boolean => typeof platform.query[mode] === 'function'
export function buildAsset(platformId: string, mode: string, target: AssetTarget | null | undefined): Record<string, any> | null {
  const platform = getPlatform(platformId)
  if (!platform || !target || !target.domain) return null
  const builder = platform.query[mode]
  if (!builder) return null
  if ((mode === 'fingerprint' || mode === 'icp') && !(target.keyword || '').trim()) return null
  try {
    const q = builder({ domain: target.domain, keyword: target.keyword || '' })
    return { query: q, url: platform.url(q), platform: platform.name, mode }
  } catch {
    return null
  }
}
