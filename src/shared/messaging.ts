// 与 background 的消息封装：把 chrome.runtime.sendMessage 的回调式统一 Promise 化。
import type { Settings } from '../types'

/** 页面侧实时状态快照：background 串行写入 chrome.storage.local 的 liveState 键，与采集结果分离 */
export interface LiveSnapshot {
  /** 回传来源站点键（url-utils.getAllInSiteKey，小写 hostname） */
  siteKey?: string
  frameworkDetection?: any
  routerAnalysis?: any
  allInStatus?: any
  apiExtractResult?: any
  /** API 提取实时进度文本（来自 api-extractor 的 PROGRESS 回传） */
  apiProgress?: string
  errors?: Record<string, string>
  updatedAt?: number
}

export interface StateResponse {
  ok: boolean
  settings: Settings
  hasCache: boolean
  lastBundle: any | null
  live?: LiveSnapshot
}
export interface CollectResponse {
  ok: boolean
  bundle?: any
  error?: string
  hint?: string
  host?: string
}
export interface ProbesResponse {
  ok: boolean
  results?: any[]
  routes?: any
  error?: string
}

function send<T>(msg: Record<string, any>): Promise<T> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (resp) => resolve((resp || { ok: false }) as T))
    } catch (e: any) {
      resolve({ ok: false, error: String((e && e.message) || e) } as unknown as T)
    }
  })
}

export const getState = (host?: string): Promise<StateResponse> => send<StateResponse>({ type: 'GET_STATE', host })
export const setSettings = (patch: Partial<Settings>): Promise<{ ok: boolean }> => send({ type: 'SET_SETTINGS', patch })
export const collect = (tabId: number): Promise<CollectResponse> => send<CollectResponse>({ type: 'COLLECT', tabId })
export const runProbes = (origin: string, host: string, tabId: number): Promise<ProbesResponse> => send<ProbesResponse>({ type: 'RUN_PROBES', origin, host, tabId })
export const openResult = (): Promise<{ ok: boolean }> => send({ type: 'OPEN_RESULT' })

// ---- 采集历史 ----
export interface HistoryResponse { ok: boolean; bundles?: any[]; error?: string }
export const listBundles = (): Promise<HistoryResponse> => send<HistoryResponse>({ type: 'LIST_BUNDLES' })
export const openBundle = (id: string): Promise<{ ok: boolean; bundle?: any; error?: string }> => send({ type: 'OPEN_BUNDLE', id })
export const deleteBundle = (id: string): Promise<HistoryResponse> => send<HistoryResponse>({ type: 'DELETE_BUNDLE', id })
export const useBundle = (id: string): Promise<{ ok: boolean; error?: string; hint?: string }> => send({ type: 'USE_BUNDLE', id })
export const clearBundles = (): Promise<HistoryResponse> => send<HistoryResponse>({ type: 'CLEAR_BUNDLES' })

/** 向指定 tab 的 content script 发送指令（detectFramework / analyzeRouter / getAllInStatus / extractApi） */
export function sendToContent<T = any>(tabId: number, action: string, extra?: Record<string, unknown>): Promise<T> {
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, { action, ...extra }, (resp) => {
        resolve((resp || { ok: false, error: 'no-response' }) as T)
      })
    } catch (e: any) {
      resolve({ ok: false, error: String((e && e.message) || e) } as unknown as T)
    }
  })
}

/** 通过 background 转发指令到 content script（popup/result/options 统一入口） */
export function forwardToContent<T = any>(tabId: number, action: string, extra?: Record<string, unknown>): Promise<T> {
  return send<T>({ type: 'FORWARD_TO_CONTENT', tabId, contentAction: action, ...extra })
}