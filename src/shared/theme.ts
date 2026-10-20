// 主题应用：把主题令牌写入 :root，切换 Element Plus 明/暗基类，并设置 body 基础色/字体。
import { THEME_TOKENS, isThemeId, DEFAULT_THEME, type ThemeId } from '../core/themes'

export function resolveTheme(raw: unknown): ThemeId {
  return isThemeId(raw) ? raw : DEFAULT_THEME
}

export function applyTheme(id: ThemeId): void {
  const html = document.documentElement
  const vars = THEME_TOKENS[id]
  for (const key in vars) html.style.setProperty(key, vars[key])
  // 暗色与极客走 Element Plus 的 dark 基类以正确渲染滚动条/禁用态等
  html.classList.toggle('dark', id !== 'light')
  html.setAttribute('data-theme', id)
  html.style.colorScheme = id === 'light' ? 'light' : 'dark'
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
