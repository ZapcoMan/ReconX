/**
 * 综合报告导出为 Markdown 格式（包含所有功能模块的信息）。
 *
 * 报告内容：
 *   1. 梭哈模式拦截统计
 *   2. 路由分析结果
 *   3. API 端点提取结果
 *   4. 安全审计报告
 */

import type { ReconBundle } from '../types'

const RISK_ICONS: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    safe: '✅'
}

const RISK_LABELS: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    safe: '安全'
}

function escapeMarkdown(text: string): string {
    return text.replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

interface AllInStatus {
    injected: boolean
    injectedAt: number
    routersPatched: number
    guardRegistrationBlocked: number
    routerJumpBlocked: number
    browserJumpBlocked: number
    lastEvent: string
}

interface UrlItem {
    path: string
    url: string
}

export interface FullReportData {
    pageUrl: string
    allInStatus?: AllInStatus | null
    routerAnalysis?: {
        framework: string
        vueVersion?: string
        reactVersion?: string
        routerDetected: boolean
        routerBase?: string | null
        routeCount?: number
        allRoutes?: Array<{ path?: string; name?: string; meta?: Record<string, unknown> }>
        modifiedRoutes?: Array<{ path?: string; name?: string }>
        pageAnalysis?: { detectedBasePath: string }
        logs?: Array<{ type: string; message: string }>
    } | null
    routeFullUrls?: UrlItem[]
    apiExtract?: {
        extractedAt: number
        scriptCount: number
        inlineScriptCount: number
        failedScripts: Array<{ url: string; error: string }>
        liveApis: Array<{ url: string; path: string }>
        staticApis: Array<{ path: string; fullUrl: string; called: boolean; sources: string[] }>
        sourceMaps: Array<{ mapUrl: string; scriptUrl: string }>
    } | null
    securityAudit?: {
        timestamp: number
        pageUrl: string
        summary: {
            overallRisk: string
            sensitiveApiCount: number
            criticalCount: number
            highCount: number
            mediumCount: number
            lowCount: number
            totalRoutes: number
            protectedRoutes: number
            unprotectedRoutes: number
            sourceMapLeakCount: number
        }
        sensitiveApis: Array<{
            path: string
            fullUrl: string
            riskLevel: string
            matchedKeyword: string
            source: string
            category: string
        }>
        unauthorizedRoutes: Array<{
            path: string
            name?: string
            riskLevel: string
            riskDescription: string
        }>
        sourceMapRisks: Array<{
            mapUrl: string
            scriptUrl: string
            riskLevel: string
            description: string
        }>
        recommendations: string[]
    } | null
}

export function generateFullReportMarkdown(data: FullReportData): string {
    const lines: string[] = []
    const now = new Date()
    const date = now.toLocaleString('zh-CN')

    lines.push('# ReconX 综合分析报告')
    lines.push('')
    lines.push('**生成时间**: ' + date)
    lines.push('**目标页面**: ' + data.pageUrl)
    lines.push('')
    lines.push('---')
    lines.push('')

    // 目录
    lines.push('## 目录')
    lines.push('')
    lines.push('- [梭哈模式拦截统计](#梭哈模式拦截统计)')
    lines.push('- [路由分析结果](#路由分析结果)')
    lines.push('- [API 端点提取结果](#api-端点提取结果)')
    if (data.securityAudit) {
        lines.push('- [安全审计报告](#安全审计报告)')
    }
    lines.push('')
    lines.push('---')
    lines.push('')

    // 1. 梭哈模式拦截统计
    lines.push('## 梭哈模式拦截统计')
    lines.push('')
    if (data.allInStatus?.injected) {
        const status = data.allInStatus
        const injectedTime = new Date(status.injectedAt).toLocaleString('zh-CN')
        lines.push('**状态**: ✅ 已注入')
        lines.push('**注入时间**: ' + injectedTime)
        lines.push('')
        lines.push('| 指标 | 数量 |')
        lines.push('|------|------|')
        lines.push('| 补丁路由数 | ' + status.routersPatched + ' |')
        lines.push('| 守卫拦截数 | ' + status.guardRegistrationBlocked + ' |')
        lines.push('| Router跳转拦截数 | ' + status.routerJumpBlocked + ' |')
        lines.push('| 浏览器跳转拦截数 | ' + status.browserJumpBlocked + ' |')
        lines.push('| 最后事件 | ' + status.lastEvent + ' |')
        lines.push('')
    } else {
        lines.push('**状态**: ❌ 未开启或未注入')
        lines.push('')
    }

    lines.push('---')
    lines.push('')

    // 2. 路由分析结果
    lines.push('## 路由分析结果')
    lines.push('')
    if (data.routerAnalysis) {
        const ra = data.routerAnalysis
        const fw = ra.framework === 'react' ? 'React' : 'Vue'
        const fwVersion = fw === 'React' ? ra.reactVersion : ra.vueVersion
        lines.push('**框架**: ' + fw)
        lines.push('**' + fw + ' 版本**: ' + (fwVersion || 'Unknown'))
        lines.push('**Router 已检测**: ' + (ra.routerDetected ? '✅ 是' : '❌ 否'))
        lines.push('**路由总数**: ' + (ra.routeCount || (ra.allRoutes?.length || 0)))
        lines.push('')

        if (ra.routerBase) {
            lines.push('**Router Base**: ' + ra.routerBase)
            lines.push('')
        }

        if (ra.pageAnalysis?.detectedBasePath) {
            lines.push('**检测到的基础路径**: ' + ra.pageAnalysis.detectedBasePath)
            lines.push('')
        }

        if (ra.modifiedRoutes && ra.modifiedRoutes.length > 0) {
            lines.push('### 已修改鉴权 Meta 的路由')
            lines.push('')
            lines.push('| 路径 | 名称 |')
            lines.push('|------|------|')
            for (const route of ra.modifiedRoutes) {
                lines.push('| ' + escapeMarkdown(route.path || '-') + ' | ' + escapeMarkdown(route.name || '-') + ' |')
            }
            lines.push('')
        }

        if (ra.allRoutes && ra.allRoutes.length > 0) {
            lines.push('### 完整路由列表')
            lines.push('')
            lines.push('| 路径 | 名称 | Meta |')
            lines.push('|------|------|------|')
            for (const route of ra.allRoutes) {
                const metaStr = route.meta ? JSON.stringify(route.meta) : '-'
                lines.push('| ' + escapeMarkdown(route.path || '-') + ' | ' + escapeMarkdown(route.name || '-') + ' | ' + escapeMarkdown(metaStr) + ' |')
            }
            lines.push('')
        }

        if (data.routeFullUrls && data.routeFullUrls.length > 0) {
            lines.push('### 路由完整 URL 列表')
            lines.push('')
            lines.push('共 ' + data.routeFullUrls.length + ' 条可访问 URL：')
            lines.push('')
            lines.push('| 路由路径 | 完整 URL |')
            lines.push('|----------|----------|')
            for (const item of data.routeFullUrls) {
                lines.push('| ' + escapeMarkdown(item.path) + ' | ' + escapeMarkdown(item.url) + ' |')
            }
            lines.push('')
        }

        if (ra.logs && ra.logs.length > 0) {
            lines.push('### 分析日志')
            lines.push('')
            for (const log of ra.logs) {
                const typeLabel = log.type === 'warn' ? '⚠️' : log.type === 'error' ? '❌' : 'ℹ️'
                lines.push(typeLabel + ' ' + (log.message || ''))
            }
            lines.push('')
        }
    } else {
        lines.push('未进行路由分析')
        lines.push('')
    }

    lines.push('---')
    lines.push('')

    // 3. API 端点提取结果
    lines.push('## API 端点提取结果')
    lines.push('')
    if (data.apiExtract) {
        const api = data.apiExtract
        lines.push('**提取时间**: ' + new Date(api.extractedAt).toLocaleString('zh-CN'))
        lines.push('**扫描 JS 文件数**: ' + api.scriptCount)
        lines.push('**内联脚本数**: ' + api.inlineScriptCount)
        if (api.failedScripts.length > 0) {
            lines.push('**失败脚本数**: ' + api.failedScripts.length)
        }
        lines.push('')

        // 实际调用 API
        lines.push('### 实际调用接口 (' + api.liveApis.length + ' 条)')
        lines.push('')
        if (api.liveApis.length > 0) {
            lines.push('| URL | 路径 |')
            lines.push('|-----|------|')
            for (const item of api.liveApis) {
                lines.push('| ' + escapeMarkdown(item.url) + ' | ' + escapeMarkdown(item.path) + ' |')
            }
            lines.push('')
        } else {
            lines.push('暂无（操作一下页面再重新提取可捕获真实请求）')
            lines.push('')
        }

        // JS 静态提取 API
        const uncalledCount = api.staticApis.filter(item => !item.called).length
        lines.push('### JS 源码静态提取接口 (' + api.staticApis.length + ' 条，未调用 ' + uncalledCount + ' 条)')
        lines.push('')
        if (api.staticApis.length > 0) {
            lines.push('| 路径 | 完整 URL | 状态 | 来源 |')
            lines.push('|------|----------|------|------|')
            for (const item of api.staticApis) {
                const status = item.called ? '已调用' : '未调用'
                const sources = item.sources.length > 0 ? item.sources.join(', ') : '-'
                lines.push('| ' + escapeMarkdown(item.path) + ' | ' + escapeMarkdown(item.fullUrl) + ' | ' + status + ' | ' + escapeMarkdown(sources) + ' |')
            }
            lines.push('')
        } else {
            lines.push('未提取到端点')
            lines.push('')
        }

        // Sourcemap 泄露
        if (api.sourceMaps.length > 0) {
            lines.push('### Sourcemap 泄露 (' + api.sourceMaps.length + ' 个)')
            lines.push('')
            lines.push('| Sourcemap URL | 脚本 URL |')
            lines.push('|---------------|-----------|')
            for (const map of api.sourceMaps) {
                lines.push('| ' + escapeMarkdown(map.mapUrl) + ' | ' + escapeMarkdown(map.scriptUrl) + ' |')
            }
            lines.push('')
        }
    } else {
        lines.push('未进行 API 提取')
        lines.push('')
    }

    lines.push('---')
    lines.push('')

    // 4. 安全审计报告
    if (data.securityAudit) {
        const report = data.securityAudit
        const date = new Date(report.timestamp).toLocaleString('zh-CN')

        lines.push('## 安全审计报告')
        lines.push('')
        lines.push('**审计时间**: ' + date)
        lines.push('')
        const icon = RISK_ICONS[report.summary.overallRisk] || ''
        const label = RISK_LABELS[report.summary.overallRisk] || ''
        lines.push('**整体风险等级**: ' + icon + ' ' + label)
        lines.push('')
        lines.push('| 指标 | 数量 |')
        lines.push('|------|------|')
        lines.push('| 敏感 API 总数 | ' + report.summary.sensitiveApiCount + ' |')
        lines.push('| 严重风险 | ' + report.summary.criticalCount + ' |')
        lines.push('| 高危 | ' + report.summary.highCount + ' |')
        lines.push('| 中危 | ' + report.summary.mediumCount + ' |')
        lines.push('| 低危 | ' + report.summary.lowCount + ' |')
        lines.push('| 路由总数 | ' + report.summary.totalRoutes + ' |')
        lines.push('| 已保护路由 | ' + report.summary.protectedRoutes + ' |')
        lines.push('| 未保护路由 | ' + report.summary.unprotectedRoutes + ' |')
        lines.push('| Sourcemap 泄露 | ' + report.summary.sourceMapLeakCount + ' |')
        lines.push('')

        if (report.sensitiveApis.length > 0) {
            lines.push('### 敏感 API 检测结果')
            lines.push('')
            lines.push('共发现 **' + report.sensitiveApis.length + '** 个敏感 API 端点')
            lines.push('')

            const grouped: Record<string, typeof report.sensitiveApis> = {}
            for (const api of report.sensitiveApis) {
                if (!grouped[api.category]) {
                    grouped[api.category] = []
                }
                grouped[api.category].push(api)
            }

            for (const category of Object.keys(grouped)) {
                const apis = grouped[category]
                lines.push('#### ' + category + ' (' + apis.length + ' 个)')
                lines.push('')
                lines.push('| 路径 | 完整 URL | 风险等级 | 匹配关键词 | 来源 |')
                lines.push('|------|----------|----------|------------|------|')

                for (const api of apis) {
                    const aIcon = RISK_ICONS[api.riskLevel] || ''
                    const aLabel = RISK_LABELS[api.riskLevel] || ''
                    const sourceLabel = api.source === 'live' ? '已调用' : '静态提取'
                    lines.push('| ' + escapeMarkdown(api.path) + ' | ' + escapeMarkdown(api.fullUrl) + ' | ' + aIcon + ' ' + aLabel + ' | ' + api.matchedKeyword + ' | ' + sourceLabel + ' |')
                }

                lines.push('')
            }
        } else {
            lines.push('### 敏感 API 检测结果')
            lines.push('')
            lines.push('未发现敏感 API 端点')
            lines.push('')
        }

        if (report.unauthorizedRoutes.length > 0) {
            lines.push('### 未授权访问路径')
            lines.push('')
            lines.push('共发现 **' + report.unauthorizedRoutes.length + '** 个未受保护的路由')
            lines.push('')
            lines.push('| 路径 | 路由名称 | 风险等级 | 风险描述 |')
            lines.push('|------|----------|----------|----------|')

            for (const route of report.unauthorizedRoutes) {
                const rIcon = RISK_ICONS[route.riskLevel] || ''
                const rLabel = RISK_LABELS[route.riskLevel] || ''
                const name = route.name || '-'
                lines.push('| ' + escapeMarkdown(route.path) + ' | ' + escapeMarkdown(name) + ' | ' + rIcon + ' ' + rLabel + ' | ' + route.riskDescription + ' |')
            }

            lines.push('')
        } else {
            lines.push('### 未授权访问路径')
            lines.push('')
            lines.push('所有路由均有权限保护')
            lines.push('')
        }

        if (report.sourceMapRisks.length > 0) {
            lines.push('### Sourcemap 泄露风险')
            lines.push('')
            lines.push('共发现 **' + report.sourceMapRisks.length + '** 个 Sourcemap 泄露')
            lines.push('')
            lines.push('| Sourcemap URL | 脚本 URL | 风险等级 | 说明 |')
            lines.push('|---------------|-----------|----------|------|')

            for (const sm of report.sourceMapRisks) {
                const smIcon = RISK_ICONS[sm.riskLevel] || ''
                const smLabel = RISK_LABELS[sm.riskLevel] || ''
                lines.push('| ' + escapeMarkdown(sm.mapUrl) + ' | ' + escapeMarkdown(sm.scriptUrl) + ' | ' + smIcon + ' ' + smLabel + ' | ' + sm.description + ' |')
            }

            lines.push('')
        } else {
            lines.push('### Sourcemap 泄露风险')
            lines.push('')
            lines.push('未发现 Sourcemap 泄露')
            lines.push('')
        }

        if (report.recommendations.length > 0) {
            lines.push('### 安全建议')
            lines.push('')
            for (const rec of report.recommendations) {
                lines.push('- ' + rec)
            }
            lines.push('')
        }

        lines.push('---')
        lines.push('')
    }

    lines.push('*本报告由 ReconX Chrome 扩展自动生成*')

    return lines.join('\n')
}

/** 从 ReconBundle 中提取 FullReportData */
export function bundleToReportData(bundle: ReconBundle, pageUrl: string): FullReportData {
    const allInStatus: AllInStatus | null = (bundle.probes && bundle.probes.allIn) || null
    const routerAnalysis = bundle.routes ? {
        framework: bundle.routes.framework || 'unknown',
        vueVersion: bundle.routes.vueVersion || undefined,
        reactVersion: bundle.routes.reactVersion || undefined,
        routerDetected: bundle.routes.routerDetected || false,
        routerBase: bundle.routes.routerBase || null,
        routeCount: bundle.routes.allRoutesCount || 0,
        allRoutes: bundle.routes.allRoutes || [],
        modifiedRoutes: bundle.routes.modifiedRoutes || [],
        pageAnalysis: bundle.routes.pageAnalysis || undefined,
        logs: bundle.routes.logs || []
    } : null

    const routeFullUrls: UrlItem[] | undefined = bundle.probes && bundle.probes.routes && bundle.probes.routes.routeFullUrls

    const apiExtract = bundle.api ? {
        extractedAt: bundle.api.extractedAt || Date.now(),
        scriptCount: bundle.api.scriptCount || 0,
        inlineScriptCount: bundle.api.inlineScriptCount || 0,
        failedScripts: bundle.api.failedScripts || [],
        liveApis: bundle.api.liveApis || [],
        staticApis: bundle.api.staticApis || [],
        sourceMaps: bundle.api.sourceMaps || []
    } : null

    const securityAudit = bundle.security ? {
        timestamp: bundle.security.timestamp || Date.now(),
        pageUrl: bundle.security.pageUrl || pageUrl,
        summary: bundle.security.summary || {},
        sensitiveApis: bundle.security.sensitiveApis || [],
        unauthorizedRoutes: bundle.security.unauthorizedRoutes || [],
        sourceMapRisks: bundle.security.sourceMapRisks || [],
        recommendations: bundle.security.recommendations || []
    } : null

    return {
        pageUrl,
        allInStatus,
        routerAnalysis,
        routeFullUrls,
        apiExtract,
        securityAudit
    }
}

/** 一键生成 ReconBundle 的 Markdown 报告 */
export function generateBundleReportMarkdown(bundle: ReconBundle, pageUrl: string): string {
    const data = bundleToReportData(bundle, pageUrl)
    return generateFullReportMarkdown(data)
}