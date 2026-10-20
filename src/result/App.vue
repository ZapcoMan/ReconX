<template>
  <div class="res" v-if="bundle">
    <header class="bar">
      <h1>ReconX 采集结果</h1>
      <span class="u">{{ bundle.meta.url }}</span>
      <el-button size="small" @click="copyRaw">复制原始 JSON</el-button>
    </header>

    <el-tabs v-model="tab" class="tabs">
      <el-tab-pane label="概览" name="overview">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="主机">{{ bundle.meta.host }}</el-descriptions-item>
          <el-descriptions-item label="采集时间">{{ new Date(bundle.meta.collectedAt).toLocaleString('zh-CN') }}</el-descriptions-item>
          <el-descriptions-item label="框架">{{ (bundle.routes && bundle.routes.framework) || '-' }} {{ (bundle.routes && (bundle.routes.vueVersion || bundle.routes.reactVersion)) || '' }}</el-descriptions-item>
          <el-descriptions-item label="路由库">{{ (bundle.routes && bundle.routes.routerKind) || '-' }}</el-descriptions-item>
          <el-descriptions-item label="端点总数">{{ (bundle.links && bundle.links.total) || 0 }}</el-descriptions-item>
          <el-descriptions-item label="同源端点">{{ (bundle.links && bundle.links.sameOriginCount) || 0 }}</el-descriptions-item>
        </el-descriptions>
        <h3>风险摘要</h3>
        <el-table :data="bundle.risks || []" size="small" max-height="260">
          <el-table-column prop="level" label="等级" width="90" />
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="summary" label="摘要" />
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="技术栈" name="tech">
        <el-table :data="techRows" size="small">
          <el-table-column prop="name" label="名称" width="200" />
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="version" label="版本" width="120" />
          <el-table-column prop="confidence" label="置信" width="80" />
          <el-table-column label="证据"><template #default="{ row }">{{ (row.evidence || []).join(' ; ') }}</template></el-table-column>
        </el-table>
        <h3>WAF / 边缘防护</h3>
        <el-table :data="bundle.waf || []" size="small">
          <el-table-column prop="name" label="名称" width="200" />
          <el-table-column prop="vendor" label="厂商" width="160" />
          <el-table-column label="证据"><template #default="{ row }">{{ (row.evidence || []).join(', ') }}</template></el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="路由" name="routes">
        <div class="tip">框架：{{ (bundle.routes && bundle.routes.framework) || '-' }} · {{ (bundle.routes && bundle.routes.routerKind) || '未检出路由' }} · 基础路径 {{ (bundle.routes && bundle.routes.routerBase) || '-' }} · 计数 {{ (bundle.routes && bundle.routes.allRoutesCount) || 0 }}</div>
        <el-table :data="(bundle.routes && bundle.routes.allRoutes) || []" size="small" max-height="420">
          <el-table-column prop="path" label="路径" />
          <el-table-column prop="name" label="名称" width="180" />
          <el-table-column label="meta" width="260"><template #default="{ row }"><code>{{ JSON.stringify(row.meta || {}) }}</code></template></el-table-column>
        </el-table>
      </el-tab-pane>
      <el-tab-pane label="API" name="api">
        <h3>已调用接口（performance fetch/xhr）</h3>
        <el-table :data="(bundle.api && bundle.api.liveApis) || []" size="small" max-height="220">
          <el-table-column prop="path" label="路径" />
          <el-table-column label="URL"><template #default="{ row }"><code>{{ row.url }}</code></template></el-table-column>
        </el-table>
        <h3>静态提取端点（含是否被调用）</h3>
        <el-table :data="(bundle.api && bundle.api.staticApis) || []" size="small" max-height="320">
          <el-table-column prop="path" label="路径" />
          <el-table-column label="已调用" width="90"><template #default="{ row }">{{ row.called ? '是' : '否' }}</template></el-table-column>
          <el-table-column prop="hasParams" label="含参数" width="90" />
          <el-table-column label="来源"><template #default="{ row }">{{ (row.sources || []).join(', ') }}</template></el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="安全" name="security">
        <template v-if="bundle.security">
          <el-alert :title="'整体风险：' + bundle.security.summary.overallRisk + ' · 敏感API ' + bundle.security.summary.sensitiveApiCount + ' · 未保护路由 ' + bundle.security.summary.unprotectedRoutes" type="warning" :closable="false" />
          <h3>敏感接口线索</h3>
          <el-table :data="bundle.security.sensitiveApis || []" size="small" max-height="260">
            <el-table-column prop="category" label="类别" width="120" />
            <el-table-column prop="riskLevel" label="风险" width="90" />
            <el-table-column prop="path" label="路径" />
            <el-table-column prop="source" label="来源" width="90" />
          </el-table>
          <h3>建议</h3>
          <ul><li v-for="(r, i) in bundle.security.recommendations || []" :key="i">{{ r }}</li></ul>
        </template>
        <div v-else class="empty">未生成安全审计。</div>
      </el-tab-pane>

      <el-tab-pane label="主动探测" name="probes">
        <template v-if="bundle.probes && bundle.probes.performed">
          <el-table :data="bundle.probes.results || []" size="small" max-height="360">
            <el-table-column prop="path" label="路径" />
            <el-table-column prop="status" label="状态" width="80" />
            <el-table-column prop="bytes" label="字节" width="90" />
            <el-table-column label="命中" width="80"><template #default="{ row }">{{ row.matched ? '命中' : '' }}</template></el-table-column>
            <el-table-column prop="desc" label="说明" />
          </el-table>
          <template v-if="bundle.probes.routes && bundle.probes.routes.applicable">
            <h3>前端路由可达性（{{ bundle.probes.routes.framework }} · {{ bundle.probes.routes.routerKind }}）</h3>
            <el-table :data="bundle.probes.routes.routeProbes || []" size="small" max-height="320">
              <el-table-column prop="path" label="路由" />
              <el-table-column prop="status" label="状态" width="80" />
              <el-table-column prop="bytes" label="字节" width="90" />
              <el-table-column label="URL"><template #default="{ row }"><code>{{ row.url }}</code></template></el-table-column>
            </el-table>
          </template>
          <div v-else-if="bundle.probes.routes" class="tip">{{ bundle.probes.routes.reason }}</div>
        </template>
        <div v-else class="empty">未执行主动探测（需在范围内点击“主动探测”）。</div>
      </el-tab-pane>

      <el-tab-pane label="实时回传" name="live">
        <div class="tip">本页数据由页面脚本（detector / api-extractor / all-in）实时回传，与采集结果分键存储。最近更新：{{ liveTime }}</div>

        <h3>框架检测</h3>
        <el-descriptions v-if="live.frameworkDetection" :column="3" border size="small">
          <el-descriptions-item label="检出">{{ live.frameworkDetection.detected ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="框架">{{ live.frameworkDetection.framework || '-' }}</el-descriptions-item>
          <el-descriptions-item label="路由库">{{ live.frameworkDetection.routerKind || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Vue 版本">{{ live.frameworkDetection.vueVersion || '-' }}</el-descriptions-item>
          <el-descriptions-item label="React 版本">{{ live.frameworkDetection.reactVersion || '-' }}</el-descriptions-item>
          <el-descriptions-item label="路由已检出">{{ live.frameworkDetection.routerDetected ? '是' : '否' }}</el-descriptions-item>
        </el-descriptions>
        <div v-else class="empty">暂无框架检测回传。</div>

        <h3>拦截统计</h3>
        <el-descriptions v-if="liveAllIn" :column="3" border size="small">
          <el-descriptions-item label="已注入">{{ liveAllIn.injected ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="注入时间">{{ new Date(liveAllIn.injectedAt).toLocaleString('zh-CN') }}</el-descriptions-item>
          <el-descriptions-item label="最后事件">{{ liveAllIn.lastEvent || '-' }}</el-descriptions-item>
          <el-descriptions-item label="补丁路由数">{{ liveAllIn.routersPatched || 0 }}</el-descriptions-item>
          <el-descriptions-item label="守卫拦截数">{{ liveAllIn.guardRegistrationBlocked || 0 }}</el-descriptions-item>
          <el-descriptions-item label="Router 跳转拦截">{{ liveAllIn.routerJumpBlocked || 0 }}</el-descriptions-item>
          <el-descriptions-item label="浏览器跳转拦截">{{ liveAllIn.browserJumpBlocked || 0 }}</el-descriptions-item>
        </el-descriptions>
        <div v-else class="empty">暂无拦截统计回传。</div>

        <h3>路由分析（{{ liveRoutes.length }} 条）</h3>
        <el-table v-if="liveRoutes.length" :data="liveRoutes" size="small" max-height="320">
          <el-table-column prop="path" label="路径" />
          <el-table-column prop="name" label="名称" width="180" />
          <el-table-column label="meta" width="260"><template #default="{ row }"><code>{{ JSON.stringify(row.meta || {}) }}</code></template></el-table-column>
        </el-table>
        <div v-else class="empty">暂无路由分析回传。</div>

        <h3>API 提取</h3>
        <template v-if="liveApi">
          <div class="tip">已调用 {{ liveApiStats.liveCount }} · 静态 {{ liveApiStats.staticCount }}（未调用 {{ liveApiStats.uncalledCount }}） · Sourcemap {{ liveApiStats.sourceMapCount }} · JS {{ liveApiStats.scriptCount }} 个 / 内联 {{ liveApiStats.inlineCount }} 段 / 失败 {{ liveApiStats.failedCount }} 个</div>
          <el-table :data="(liveApi.staticApis || []).slice(0, 400)" size="small" max-height="320">
            <el-table-column prop="path" label="路径" />
            <el-table-column label="完整 URL"><template #default="{ row }"><code>{{ row.fullUrl || row.url || row.path }}</code></template></el-table-column>
            <el-table-column label="已调用" width="90"><template #default="{ row }">{{ row.called ? '是' : '否' }}</template></el-table-column>
            <el-table-column label="来源" width="180"><template #default="{ row }">{{ (row.sources || []).join(', ') }}</template></el-table-column>
          </el-table>
        </template>
        <div v-else class="empty">暂无 API 提取回传。</div>

        <template v-if="liveErrors.length">
          <h3>回传错误</h3>
          <ul><li v-for="[k, v] in liveErrors" :key="k"><code>{{ k }}</code> — {{ v }}</li></ul>
        </template>
      </el-tab-pane>

      <el-tab-pane label="Dork 与资产测绘" name="dork">
        <div class="bar" style="margin-bottom:8px">
          <el-select v-model="dorkEngine" size="small" style="width:120px">
            <el-option label="Google" value="google" />
            <el-option label="Bing" value="bing" />
            <el-option label="Baidu" value="baidu" />
          </el-select>
          <span class="tip">仅生成查询，请在你已获授权的范围内自行打开。</span>
        </div>
        <el-table :data="dorkItems" size="small" max-height="300">
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="name" label="名称" width="160" />
          <el-table-column prop="risk" label="风险" width="80" />
          <el-table-column label="查询"><template #default="{ row }"><code>{{ row.query }}</code></template></el-table-column>
          <el-table-column label="" width="90"><template #default="{ row }"><el-button size="small" text @click="copyText(row.url)">复制链接</el-button></template></el-table-column>
        </el-table>
        <h3>资产测绘查询（{{ bundle.meta.host }}）</h3>
        <el-table :data="assetRows" size="small" max-height="260">
          <el-table-column prop="platform" label="平台" width="140" />
          <el-table-column prop="mode" label="模式" width="120" />
          <el-table-column label="查询"><template #default="{ row }"><code>{{ row.query }}</code></template></el-table-column>
          <el-table-column label="" width="90"><template #default="{ row }"><el-button size="small" text @click="copyText(row.url)">复制链接</el-button></template></el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="原始 JSON" name="raw">
        <pre class="rawjson" @click="selectPre">{{ JSON.stringify(bundle, null, 2) }}</pre>
      </el-tab-pane>
    </el-tabs>
  </div>
  <div v-else class="empty">尚无采集结果，请在弹窗中采集后打开本页。</div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { applyTheme, resolveTheme } from '../shared/theme'
import { listPackage, toSearchItems } from '../core/dork-library'
import { PLATFORMS, ASSET_MODES, buildAsset } from '../core/asset-search'
const bundle = ref<any>(null)
const live = ref<any>({ updatedAt: 0 })
const tab = ref('overview')

const techRows = computed(() => {
  const ts = bundle.value && bundle.value.techStack
  if (ts && ts.items && ts.items.length) return ts.items
  return (bundle.value && bundle.value.tech) || []
})

const liveTime = computed(() => (live.value.updatedAt ? new Date(live.value.updatedAt).toLocaleString('zh-CN') : '—'))
const liveRoutes = computed<any[]>(() => (live.value.routerAnalysis && live.value.routerAnalysis.allRoutes) || [])
const liveAllIn = computed<any | null>(() => (live.value.allInStatus && live.value.allInStatus.injectedAt ? live.value.allInStatus : null))
const liveApi = computed<any | null>(() => live.value.apiExtractResult || null)
const liveApiStats = computed(() => {
  const a = liveApi.value
  const statics: any[] = (a && a.staticApis) || []
  return {
    liveCount: ((a && a.liveApis) || []).length,
    staticCount: statics.length,
    uncalledCount: statics.filter((x: any) => !x.called).length,
    sourceMapCount: ((a && a.sourceMaps) || []).length,
    scriptCount: (a && a.scriptCount) || 0,
    inlineCount: (a && a.inlineScriptCount) || 0,
    failedCount: ((a && a.failedScripts) || []).length
  }
})
const liveErrors = computed<Array<[string, string]>>(() => Object.entries((live.value.errors || {}) as Record<string, string>))

onMounted(async () => {
  const { lastBundle, settings, liveState } = await chrome.storage.local.get(['lastBundle', 'settings', 'liveState'])
  applyTheme(resolveTheme(settings && settings.theme))
  bundle.value = lastBundle || null
  live.value = liveState || { updatedAt: 0 }
})

async function copyRaw(): Promise<void> {
  const text = JSON.stringify(bundle.value, null, 2)
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
const dorkEngine = ref('google')
const dorkItems = computed(() => {
  const host = bundle.value && bundle.value.meta && bundle.value.meta.host
  if (!host) return []
  return toSearchItems(listPackage('general'), host, dorkEngine.value).slice(0, 60)
})
const assetRows = computed(() => {
  const host = bundle.value && bundle.value.meta && bundle.value.meta.host
  const rows: Array<{ platform: string; mode: string; url: string; query: string }> = []
  if (!host) return rows
  for (const p of PLATFORMS) for (const m of ASSET_MODES) {
    const built = buildAsset(p.id, m.id, { domain: host })
    if (built) rows.push({ platform: built.platform, mode: m.name, url: built.url, query: built.query })
  }
  return rows
})
function copyText(text: string): void {
  try {
    navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
function selectPre(e: MouseEvent): void {
  const el = e.target as HTMLElement
  const range = document.createRange()
  range.selectNodeContents(el)
  const sel = window.getSelection()
  sel?.removeAllRanges()
  sel?.addRange(range)
}
</script>

<style scoped>
.res { max-width: 1180px; margin: 0 auto; padding: 18px 22px 40px; font: 14px/1.6 var(--rx-font); color: var(--rx-text); }
.bar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.bar h1 { font-family: var(--rx-font-head); font-size: 18px; margin: 0; color: var(--rx-accent); text-shadow: var(--rx-glow); }
.u { flex: 1; color: var(--rx-muted); font-family: var(--rx-font); font-size: 12px; word-break: break-all; }
h3 { margin: 18px 0 8px; font-size: 14px; color: var(--rx-text); }
.tip { color: var(--rx-muted); font-size: 12px; margin-bottom: 8px; }
.empty { padding: 40px; text-align: center; color: var(--rx-muted); }
.rawjson { background: var(--rx-code-bg); color: var(--rx-text); padding: 14px; border-radius: 8px; box-shadow: var(--rx-glow); max-height: 560px; overflow: auto; font-family: var(--rx-font); font-size: 12px; white-space: pre-wrap; word-break: break-all; user-select: text; cursor: text; }
</style>
