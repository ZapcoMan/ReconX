// 主题应用：把主题令牌写入 :root，切换 Element Plus 明/暗基类，并设置 body 基础色/字体。
// system 没有自己的令牌：它按 prefers-color-scheme 解析成 dark 或 light 再应用，
// 并在跟随期间监听系统变化实时重应用。跟随系统与主动切换互不排斥——下拉选任意具体主题
// 即离开跟随，选回 system 即重新跟随，两条路都始终可用。
import { THEME_TOKENS, isThemeId, isConcreteThemeId, DEFAULT_THEME, type ThemeId, type ConcreteThemeId } from '../core/themes'

export function resolveTheme(raw: unknown): ThemeId {
  return isThemeId(raw) ? raw : DEFAULT_THEME
}

const prefersDark = (): boolean => {
  try {
    return !!(globalThis.matchMedia && globalThis.matchMedia('(prefers-color-scheme: dark)').matches)
  } catch {
    return false
  }
}

/** 把设置值折算成实际生效的主题 */
export function effectiveTheme(id: ThemeId): ConcreteThemeId {
  if (isConcreteThemeId(id)) return id
  return prefersDark() ? 'dark' : 'light'
}

let systemWatcher: MediaQueryList | null = null
let systemHandler: ((e: MediaQueryListEvent) => void) | null = null

/** 只在跟随系统时挂监听；重复调用会先摘掉旧的，避免切来切去堆积回调 */
function watchSystem(prefers: (id: ThemeId) => void): void {
  unwatchSystem()
  try {
    if (!globalThis.matchMedia) return
    systemWatcher = globalThis.matchMedia('(prefers-color-scheme: dark)')
    systemHandler = (e: MediaQueryListEvent) => prefers(e.matches ? 'dark' : 'light')
    if (systemWatcher.addEventListener) systemWatcher.addEventListener('change', systemHandler)
    else if (systemWatcher.addListener) systemWatcher.addListener(systemHandler)
  } catch { /* 无 matchMedia 环境就静态应用一次 */ }
}

function unwatchSystem(): void {
  if (!systemWatcher || !systemHandler) return
  try {
    if (systemWatcher.removeEventListener) systemWatcher.removeEventListener('change', systemHandler)
    else if (systemWatcher.removeListener) systemWatcher.removeListener(systemHandler)
  } catch { /* */ }
  systemWatcher = null
  systemHandler = null
}

export function applyTheme(id: ThemeId): void {
  const eff = effectiveTheme(id)
  if (id === 'system') watchSystem(() => applyTheme('system'))
  else unwatchSystem()
  writeTokens(eff, id)
}

function writeTokens(eff: ConcreteThemeId, setting: ThemeId): void {
  const html = document.documentElement
  const vars = THEME_TOKENS[eff]
  for (const key in vars) html.style.setProperty(key, vars[key])
  // 暗色与极客走 Element Plus 的 dark 基类以正确渲染滚动条/禁用态等
  html.classList.toggle('dark', eff !== 'light')
  // data-theme 记生效值，data-theme-setting 记用户所选（跟随系统时两者不同）
  html.setAttribute('data-theme', eff)
  html.setAttribute('data-theme-setting', setting)
  html.style.colorScheme = eff === 'light' ? 'light' : 'dark'
  const body = document.body
  if (body) {
    body.style.background = 'var(--rx-bg)'
    body.style.color = 'var(--rx-text)'
    body.style.fontFamily = 'var(--rx-font)'
  }
}

export function currentTheme(): ThemeId {
  const v = document.documentElement.getAttribute('data-theme')
  return isThemeId(v) ? v : DEFAULT_THEME
}
