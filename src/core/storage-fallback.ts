// 存储配额降级：结果默认全量落盘；仅当 chrome.storage 写入失败时，按此表截断长列表再写一次，
// 并在副本上打标记，让结果页能如实说明"这次是截断副本"。计数类字段（total / *Count）不截断。
export const STORAGE_FALLBACK_LIMITS: Record<string, number> = {
  'links.endpoints': 2000,
  'links.classified': 500,
  'api.liveApis': 300,
  'api.staticApis': 400,
  'routes.allRoutes': 300,
  'routes.fullUrls': 300
}

function cutList(target: any, path: string): void {
  const parts = path.split('.')
  const last = parts.pop() as string
  const owner = parts.reduce((o: any, k) => (o ? o[k] : null), target)
  if (owner && Array.isArray(owner[last])) owner[last] = owner[last].slice(0, STORAGE_FALLBACK_LIMITS[path])
}

/** 返回截断副本，不修改入参；reason/at 写进 storageTruncated 供界面提示 */
export function shrinkForStorage(bundle: any, reason: string): any {
  const slim = JSON.parse(JSON.stringify(bundle || {}))
  Object.keys(STORAGE_FALLBACK_LIMITS).forEach((p) => cutList(slim, p))
  slim.storageTruncated = { reason, limits: STORAGE_FALLBACK_LIMITS, at: Date.now() }
  return slim
}
