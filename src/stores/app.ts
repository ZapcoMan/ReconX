// ReconX 共享状态（Pinia）：popup/result/options 各页持有实例；范围/设置/最近结果经 messaging 与 chrome.* 同步。
import { defineStore } from 'pinia'
import * as M from '../shared/messaging'
import type { LiveSnapshot } from '../shared/messaging'
import { applyTheme, resolveTheme } from '../shared/theme'
import type { ThemeId } from '../core/themes'
import type { Scope, Settings } from '../types'

interface ActiveTab {
  tabId: number | null
  host: string
  origin: string
  url: string
}

export const useAppStore = defineStore('app', {
  state: () => ({
    scope: { hosts: [] } as Scope,
    settings: { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark' } as Settings,
    active: { tabId: null, host: '', origin: '', url: '' } as ActiveTab,
    inScope: false,
    hasCache: false,
    lastBundle: null as any | null,
    live: { updatedAt: 0 } as LiveSnapshot,
    busyAction: '' as '' | 'authorize' | 'collect' | 'probes',
    message: '' as string
  }),
  getters: {
    authorized: (s) => s.inScope
  },
  actions: {
    async queryActive(): Promise<void> {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        const url = (tab && tab.url) || ''
        let host = '', origin = ''
        try { const u = new URL(url); host = u.hostname; origin = u.origin } catch { /* */ }
        this.active = { tabId: tab && tab.id != null ? tab.id : null, host, origin, url }
      } catch {
        this.active = { tabId: null, host: '', origin: '', url: '' }
      }
    },
    async loadState(): Promise<void> {
      const st = await M.getState(this.active.host || undefined)
      if (st && st.ok) {
        this.scope = st.scope
        this.settings = st.settings
        applyTheme(resolveTheme(st.settings && st.settings.theme))
        this.inScope = st.inScope
        this.hasCache = st.hasCache
        this.lastBundle = st.lastBundle
        this.live = st.live || { updatedAt: 0 }
      }
    },
    async refresh(): Promise<void> {
      await this.queryActive()
      await this.loadState()
    },
    async authorize(): Promise<boolean> {
      if (!this.active.origin) { this.message = '当前页 URL 不支持授权'; return false }
      this.busyAction = 'authorize'
      try {
        let granted = false
        try { granted = await chrome.permissions.request({ origins: [this.active.origin + '/*'] }) } catch { granted = false }
        if (!granted) { this.message = '未获得 host 权限，无法采集'; return false }
        await M.addHost(this.active.host, this.active.origin, '')
        await this.refresh()
        this.message = '已加入允许域并授权'
        return true
      } finally {
        this.busyAction = ''
      }
    },
    async revokeHost(host: string, origin: string): Promise<void> {
      await M.removeHost(host, origin)
      await this.refresh()
    },
    async collect(): Promise<void> {
      if (this.active.tabId == null) return
      this.busyAction = 'collect'
      this.message = '采集中…'
      try {
        const r = await M.collect(this.active.tabId)
        if (r.ok && r.bundle) { this.lastBundle = r.bundle; this.message = '采集完成' }
        else this.message = r.hint || r.error || '采集失败'
      } finally {
        this.busyAction = ''
      }
    },
    async probes(): Promise<void> {
      if (this.active.tabId == null || !this.inScope) return
      this.busyAction = 'probes'
      this.message = '主动探测中…'
      try {
        const r = await M.runProbes(this.active.origin, this.active.host, this.active.tabId)
        if (r.ok) { this.message = '探测完成'; await this.loadState() }
        else this.message = r.error === 'probe_disabled' ? '主动探测已在设置页关闭' : (r.error || '探测失败')
      } finally {
        this.busyAction = ''
      }
    },
    async saveSettings(patch: Partial<Settings>): Promise<void> {
      await M.setSettings(patch)
      this.settings = Object.assign({}, this.settings, patch)
    },
    async setTheme(id: ThemeId): Promise<void> {
      applyTheme(id)
      await this.saveSettings({ theme: id })
    },
    openResult(): Promise<void> {
      return M.openResult().then(() => undefined)
    }
  }
})