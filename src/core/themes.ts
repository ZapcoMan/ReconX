// 主题令牌与注册表（暗色 / 亮色 / 极客 / 跟随系统）。纯数据：每个具体主题是一组 CSS 自定义属性，
// 由 src/shared/theme.ts 注入到 :root，页面 scoped 样式消费 var(--rx-*)，
// 并覆写 Element Plus 的关键变量使组件跟随主题。
// system 本身没有令牌：它在应用时按 prefers-color-scheme 解析成 dark 或 light。
export type ConcreteThemeId = 'dark' | 'light' | 'geek'
export type ThemeId = ConcreteThemeId | 'system'

export type CssVars = Record<string, string>

export interface ThemeMeta {
  id: ThemeId
  label: string
  desc: string
  swatch: string[]
}

const FONT_UI = "system-ui,'Microsoft YaHei',sans-serif"
const FONT_GEEK = "'JetBrains Mono','Cascadia Code',Consolas,'Courier New',monospace"

export const THEME_ORDER: ThemeId[] = ['dark', 'light', 'geek', 'system']

export const THEME_META: Record<ThemeId, ThemeMeta> = {
  dark: { id: 'dark', label: '暗色', desc: '低亮度深底高对比，适合长时间侦察', swatch: ['#0f1620', '#2dd4bf', '#e6edf3'] },
  light: { id: 'light', label: '亮色', desc: '明亮浅底，接近常规界面', swatch: ['#f5f7fa', '#0d9488', '#1f2937'] },
  geek: { id: 'geek', label: '极客', desc: '终端绿 + 等宽字体 + 辉光，黑客风', swatch: ['#050807', '#00ff9c', '#3fae7a'] },
  system: { id: 'system', label: '跟随系统', desc: '按系统 prefers-color-scheme 取暗色或亮色，系统切换时实时跟随', swatch: ['#0f1620', '#2dd4bf', '#f5f7fa'] }
}

// 每个主题的令牌：--rx-* 供本项目样式使用；--el-* 覆写 Element Plus 关键变量。
export const THEME_TOKENS: Record<ConcreteThemeId, CssVars> = {
  dark: {
    '--rx-bg': '#0f1620',
    '--rx-bg-elev': '#16212e',
    '--rx-bg-soft': '#1b2836',
    '--rx-text': '#e6edf3',
    '--rx-muted': '#94a3b8',
    '--rx-border': '#223043',
    '--rx-accent': '#2dd4bf',
    '--rx-accent-soft': '#0d3b36',
    '--rx-accent-contrast': '#04211d',
    '--rx-danger': '#ff6b6b',
    '--rx-warn': '#f6c344',
    '--rx-code-bg': '#0b1017',
    '--rx-glow': 'none',
    '--rx-font': FONT_UI,
    '--rx-font-head': FONT_UI,
    '--el-color-primary': '#2dd4bf',
    '--el-bg-color': '#16212e',
    '--el-bg-color-page': '#0f1620',
    '--el-bg-color-overlay': '#1b2836',
    '--el-text-color-primary': '#e6edf3',
    '--el-text-color-regular': '#cbd5e1',
    '--el-text-color-secondary': '#94a3b8',
    '--el-border-color': '#223043',
    '--el-border-color-lighter': '#1c2836',
    '--el-fill-color': '#1b2836',
    '--el-fill-color-light': '#16212e',
    '--el-fill-color-blank': '#0f1620',
    '--el-mask-color': 'rgba(5,8,10,0.6)'
  },
  light: {
    '--rx-bg': '#f5f7fa',
    '--rx-bg-elev': '#ffffff',
    '--rx-bg-soft': '#eef2f7',
    '--rx-text': '#1f2937',
    '--rx-muted': '#64748b',
    '--rx-border': '#dbe2ea',
    '--rx-accent': '#0d9488',
    '--rx-accent-soft': '#d1faf5',
    '--rx-accent-contrast': '#ffffff',
    '--rx-danger': '#dc2626',
    '--rx-warn': '#b45309',
    '--rx-code-bg': '#f1f5f9',
    '--rx-glow': 'none',
    '--rx-font': FONT_UI,
    '--rx-font-head': FONT_UI,
    '--el-color-primary': '#0d9488',
    '--el-bg-color': '#ffffff',
    '--el-bg-color-page': '#f5f7fa',
    '--el-bg-color-overlay': '#ffffff',
    '--el-text-color-primary': '#1f2937',
    '--el-text-color-regular': '#334155',
    '--el-text-color-secondary': '#64748b',
    '--el-border-color': '#dbe2ea',
    '--el-border-color-lighter': '#e8edf3',
    '--el-fill-color': '#eef2f7',
    '--el-fill-color-light': '#f1f5f9',
    '--el-fill-color-blank': '#ffffff',
    '--el-mask-color': 'rgba(255,255,255,0.7)'
  },
  geek: {
    '--rx-bg': '#050807',
    '--rx-bg-elev': '#0a120e',
    '--rx-bg-soft': '#0e1a12',
    '--rx-text': '#00ff9c',
    '--rx-muted': '#3fae7a',
    '--rx-border': '#0f3d24',
    '--rx-accent': '#00ff9c',
    '--rx-accent-soft': '#052a1a',
    '--rx-accent-contrast': '#03140b',
    '--rx-danger': '#ff5555',
    '--rx-warn': '#ffb000',
    '--rx-code-bg': '#030a06',
    '--rx-glow': '0 0 8px rgba(0,255,156,0.45)',
    '--rx-font': FONT_GEEK,
    '--rx-font-head': FONT_GEEK,
    '--el-color-primary': '#00ff9c',
    '--el-bg-color': '#0a120e',
    '--el-bg-color-page': '#050807',
    '--el-bg-color-overlay': '#0e1a12',
    '--el-text-color-primary': '#00ff9c',
    '--el-text-color-regular': '#68d9a6',
    '--el-text-color-secondary': '#3fae7a',
    '--el-border-color': '#0f3d24',
    '--el-border-color-lighter': '#0a2a19',
    '--el-fill-color': '#0e1a12',
    '--el-fill-color-light': '#0a120e',
    '--el-fill-color-blank': '#050807',
    '--el-mask-color': 'rgba(3,10,6,0.7)'
  }
}

export const DEFAULT_THEME: ThemeId = 'dark'

export function isThemeId(v: unknown): v is ThemeId {
  return v === 'dark' || v === 'light' || v === 'geek' || v === 'system'
}

export function isConcreteThemeId(v: unknown): v is ConcreteThemeId {
  return v === 'dark' || v === 'light' || v === 'geek'
}
