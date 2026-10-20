// 与 background 的消息封装：把 chrome.runtime.sendMessage 的回调式统一 Promise 化。
import type { Scope, Settings } from '../types'

export interface StateResponse {
  ok: boolean
  scope: Scope
  settings: Settings
  inScope: boolean
  hasCache: boolean
  lastBundle: any | null
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
export const addHost = (host: string, origin: string, note?: string): Promise<{ ok: boolean }> => send({ type: 'ADD_HOST', host, origin, note })
export const removeHost = (host: string, origin?: string): Promise<{ ok: boolean; scope?: Scope }> => send({ type: 'REMOVE_HOST', host, origin })
export const setSettings = (patch: Partial<Settings>): Promise<{ ok: boolean }> => send({ type: 'SET_SETTINGS', patch })
export const collect = (tabId: number): Promise<CollectResponse> => send<CollectResponse>({ type: 'COLLECT', tabId })
export const runProbes = (origin: string, host: string, tabId: number): Promise<ProbesResponse> => send<ProbesResponse>({ type: 'RUN_PROBES', origin, host, tabId })
export const openResult = (): Promise<{ ok: boolean }> => send({ type: 'OPEN_RESULT' })

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