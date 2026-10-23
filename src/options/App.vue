<template>
  <div class="opt">
    <header class="head">
      <div class="head-txt">
        <h1>设置与范围管理</h1>
        <p class="sub">允许域决定 ReconX 能在哪些主机上工作；采集参数与主动探测开关决定它做多少事。</p>
      </div>
      <div class="chips">
        <span class="chip">允许域 <b>{{ hosts.length }}</b></span>
        <span class="chip" :class="{ on: settings.activeProbe }">主动探测 <b>{{ settings.activeProbe ? '已开启' : '已关闭' }}</b></span>
        <span class="chip">主题 <b>{{ themeMeta.label }}</b></span>
      </div>
    </header>

    <section class="block">
      <div class="block-head"><h2>外观主题</h2><span class="hint">即时生效并记住，与弹窗、结果页共用</span></div>
      <div class="theme-bar">
        <span class="sw"><i v-for="(c, i) in swatch" :key="i" :style="{ background: c }"></i></span>
        <span class="tb-txt">
          <b>{{ themeMeta.label }}</b>
          <em v-if="followSystem">当前生效：{{ effLabel }} · 系统换主题时这里会实时跟上</em>
          <em v-else>{{ themeMeta.desc }}</em>
        </span>
        <el-select :model-value="settings.theme" size="small" class="tb-sel" @change="changeTheme">
          <el-option v-for="id in THEME_ORDER" :key="id" :label="THEME_META[id].label" :value="id" />
        </el-select>
      </div>
    </section>

    <section class="block">
      <div class="block-head"><h2>采集参数</h2><span class="hint">修改即时保存</span></div>
      <div class="fields">
        <div class="field">
          <div class="f-txt">
            <b>启用主动探测</b>
            <p>开启后才允许执行敏感路径与路由可达性探测，并把常驻接管脚本注册到允许域；关闭时弹窗的探测按钮不可用，已注册的脚本会被撤销。</p>
          </div>
          <el-switch v-model="settings.activeProbe" @change="persist" />
        </div>
        <div class="field">
          <div class="f-txt">
            <b>最多扫描 JS 文件数</b>
            <p>单次采集拉取并分析的外链脚本上限，越大越慢、越容易碰到跨域失败。</p>
          </div>
          <el-input-number v-model="settings.maxJsFiles" :min="1" :max="200" size="small" controls-position="right" @change="persist" />
        </div>
        <div class="field">
          <div class="f-txt">
            <b>并发抓取数</b>
            <p>同时向目标拉取 JS 的请求数，调高会明显增加目标负载。</p>
          </div>
          <el-input-number v-model="settings.maxConcurrent" :min="1" :max="12" size="small" controls-position="right" @change="persist" />
        </div>
        <div class="field wide">
          <div class="f-txt">
            <b>链接采集黑名单</b>
            <p>命中的链接不计入采集端点，采集结果概览会如实显示被跳过的条数。支持裸域、<code>*.</code> 通配域与 <code>/正则/</code> 三种写法；搜索引擎跳转链接无需填写，默认已被排除。</p>
          </div>
          <el-input v-model="blacklistText" type="textarea" :rows="3" class="f-area" placeholder="static.example.com&#10;*.cdn.net&#10;/analytics/" @change="applyBlacklist" />
        </div>
        <div class="foot-actions">
          <el-button size="small" text @click="restoreDefaults">恢复默认参数</el-button>
        </div>
      </div>
    </section>

    <section class="block">
      <div class="block-head"><h2>扫描规则</h2><span class="hint">自定义条目只追加，内置 {{ BUILTIN_PATTERN_COUNT }} 条密钥规则与 {{ BUILTIN_PROBE_COUNT }} 条敏感路径始终生效</span></div>
      <div class="fields">
        <div class="field wide">
          <div class="f-txt">
            <b>自定义密钥正则（当前 {{ settings.userPatterns.length }} 条）</b>
            <p>JSON 数组，每条需 <code>id / name / severity / source / desc</code>，可选 <code>flags</code>（默认 gi）。<code>source</code> 写正则源码、不要 <code>//</code> 包裹，捕获组匹配到的内容会作为命中原文输出，长度上限 200 字符。整批校验通过才并入——任一条不合法都会给出序号与原因并拒绝全部。</p>
          </div>
          <el-input v-model="patternText" type="textarea" :rows="4" placeholder='[{"id":"corp_token","name":"内部令牌","severity":"high","source":"corp_token[^0-9a-f]{0,3}([0-9a-f]{20,})","desc":"内部令牌硬编码"}]' />
          <div class="bar-row">
            <el-button size="small" @click="importPatterns">校验并入</el-button>
            <el-button v-if="settings.userPatterns.length" size="small" @click="exportPatterns">导出备份</el-button>
            <el-button v-if="settings.userPatterns.length" size="small" text type="danger" @click="clearPatterns">清除自定义</el-button>
          </div>
        </div>
        <div class="field wide">
          <div class="f-txt">
            <b>自定义敏感路径探测（当前 {{ settings.userProbes.length }} 条）</b>
            <p>JSON 数组，每条需 <code>path</code>（以 / 开头）、<code>severity</code>、<code>keywords</code>（响应体含其中任一词才算命中）、<code>desc</code>。与内置条目同路径时以内置为准，不会重复发请求。</p>
          </div>
          <el-input v-model="probeText" type="textarea" :rows="4" placeholder='[{"path":"/backup.sql","severity":"high","keywords":["INSERT INTO","mysqldump"],"desc":"数据库备份泄露"}]' />
          <div class="bar-row">
            <el-button size="small" @click="importProbes">校验并入</el-button>
            <el-button v-if="settings.userProbes.length" size="small" @click="exportProbes">导出备份</el-button>
            <el-button v-if="settings.userProbes.length" size="small" text type="danger" @click="clearProbes">清除自定义</el-button>
          </div>
        </div>
      </div>
      <div v-if="ruleMsg" class="hint rule-msg">{{ ruleMsg }}</div>
    </section>

    <section class="block">
      <div class="block-head"><h2>采集历史</h2><span class="hint">每次采集自动留一份，最多 {{ HISTORY_LIMIT }} 份，超出丢弃最旧</span></div>
      <el-table v-if="history.length" :data="history" size="small" class="hosts">
        <el-table-column label="采集时间" width="158"><template #default="{ row }"><span class="mono">{{ fmt(row.collectedAt) }}</span></template></el-table-column>
        <el-table-column label="主机与内容"><template #default="{ row }"><span class="host">{{ row.host }}</span><span class="note">{{ summaryOf(row as BundleMeta) }}</span></template></el-table-column>
        <el-table-column label="" width="140" align="right">
          <template #default="{ row }">
            <el-button size="small" text @click="openInResult(row.id)">打开</el-button>
            <el-button size="small" text type="danger" @click="removeOne(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-else class="empty">尚无历史结果。采集一次后，这里就能逐份打开或删除。</div>
      <div v-if="history.length" class="hist-foot">
        <span class="hint">共 {{ history.length }} 份 · 全部只存在本机 <code>chrome.storage.local</code>，删除不可恢复</span>
        <el-button size="small" text type="danger" @click="clearHistory">清空全部历史</el-button>
      </div>
    </section>

    <section class="block">
      <div class="block-head"><h2>误报标记管理</h2><span class="hint">在结果页「标记误报」的条目集中在此。标记只影响展示与计数，原始命中始终保留</span></div>
      <el-table v-if="fpRows.length" :data="fpRows" size="small" class="hosts">
        <el-table-column label="范围" width="80"><template #default="{ row }"><span class="host">{{ row.scope === 'global' ? '全站' : '本站' }}</span></template></el-table-column>
        <el-table-column label="主机" width="220"><template #default="{ row }"><span class="host">{{ row.host }}</span></template></el-table-column>
        <el-table-column label="类型" width="110"><template #default="{ row }"><span class="note">{{ kindLabel(row.kind) }}</span></template></el-table-column>
        <el-table-column label="命中"><template #default="{ row }"><span class="mono">{{ row.key }}</span></template></el-table-column>
        <el-table-column label="" width="150" align="right">
          <template #default="{ row }">
            <el-button v-if="row.scope === 'site'" size="small" text @click="promoteFp(row.mapKey)">升为全站</el-button>
            <el-button size="small" text type="danger" @click="undoFp(row.mapKey)">撤销</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-else class="empty">尚无误报标记。在结果页对某条命中点「标记误报」后，会在此统一查看与撤销。</div>
      <div v-if="fpRows.length" class="hist-foot">
        <span class="hint">共 {{ fpRows.length }} 条 · 只存在本机 <code>chrome.storage.local</code>；「本站」标记仅对同主机生效，「全站」跨所有站点生效</span>
        <el-button size="small" text type="danger" @click="clearFps">清空全部标记</el-button>
      </div>
    </section>

    <footer class="legal">
      ReconX 仅用于你拥有或已获书面授权的目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。命中皆为线索，需人工确认，且一律以原文留存并进入导出文件。所有数据仅保存在本机浏览器，不外传。请遵守目标站点条款与当地法律。
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, toRaw } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as M from '../shared/messaging'
import type { ScopeHost, Settings } from '../types'
import { THEME_ORDER, THEME_META, type ThemeId, type ConcreteThemeId } from '../core/themes'
import { applyTheme, resolveTheme, effectiveTheme } from '../shared/theme'
import { HISTORY_LIMIT, findInIndex, describeMeta, type BundleMeta } from '../core/bundle-store'
import { parseJson, exportJson } from '../core/exporter'
import { BUILTIN_PATTERN_COUNT, BUILTIN_PROBE_COUNT, validatePatternImport, validateProbeImport, toBackupPatterns } from '../core/user-rules'
import { describeFp, withFp, withoutFp } from '../core/false-positive'

const DEFAULTS: Settings = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark', linkBlacklist: [], userPatterns: [], userProbes: [] }

const hosts = ref<ScopeHost[]>([])
const settings = reactive<Settings>({ ...DEFAULTS })
// 黑名单在设置里是 string[]，界面用多行文本编辑，两者在此互转
const blacklistText = ref('')
const themeMeta = computed(() => THEME_META[settings.theme] || THEME_META.dark)
const followSystem = computed(() => settings.theme === 'system')
// 跟随系统时，色板与"当前生效"都按实际生效的那一档显示；下拉仍可随时选回任一具体主题
const effTheme = ref<ConcreteThemeId>('dark')
const swatch = computed(() => THEME_META[effTheme.value].swatch)
const effLabel = computed(() => THEME_META[effTheme.value].label)

function syncEffective(): void {
  effTheme.value = effectiveTheme(settings.theme)
}

function applyBlacklist(): Promise<void> {
  settings.linkBlacklist = blacklistText.value.split('\n').map((s) => s.trim()).filter(Boolean)
  return persist()
}

// 采集历史：管理动作（打开/删除/清空）集中在设置页，结果页只负责切换查看
const history = ref<BundleMeta[]>([])
const summaryOf = (m: BundleMeta): string => `端点 ${m.endpoints} · 路由 ${m.routes} · 发现 ${m.findings}${m.probes ? ' · 已探测' : ''}${m.truncated ? ' · 截断副本' : ''}`

// 自定义规则：界面用 JSON 文本编辑，validate* 通过才并入并持久化；内置规则始终保留
const patternText = ref('')
const probeText = ref('')
const ruleMsg = ref('')

async function importPatterns(): Promise<void> {
  const parsed = parseJson(patternText.value)
  if (!parsed.ok) { ruleMsg.value = 'JSON 解析失败：' + parsed.error; return }
  const v = validatePatternImport(parsed.data)
  if (!v.ok) { ruleMsg.value = '密钥规则校验失败：' + v.error; return }
  settings.userPatterns = parsed.data
  await persist()
  ruleMsg.value = '已并入 ' + v.count + ' 条自定义密钥规则'
}

async function importProbes(): Promise<void> {
  const parsed = parseJson(probeText.value)
  if (!parsed.ok) { ruleMsg.value = 'JSON 解析失败：' + parsed.error; return }
  const v = validateProbeImport(parsed.data)
  if (!v.ok) { ruleMsg.value = '探测条目校验失败：' + v.error; return }
  settings.userProbes = parsed.data
  await persist()
  ruleMsg.value = '已并入 ' + v.count + ' 条自定义敏感路径探测'
}

function exportPatterns(): void { exportJson(toBackupPatterns(toRaw(settings.userPatterns)), 'reconx-user-patterns') }
function exportProbes(): void { exportJson(toRaw(settings.userProbes), 'reconx-user-probes') }

async function clearPatterns(): Promise<void> {
  settings.userPatterns = []
  patternText.value = ''
  await persist()
  ruleMsg.value = '已清除自定义密钥规则，内置 ' + BUILTIN_PATTERN_COUNT + ' 条不受影响'
}

async function clearProbes(): Promise<void> {
  settings.userProbes = []
  probeText.value = ''
  await persist()
  ruleMsg.value = '已清除自定义探测条目，内置 ' + BUILTIN_PROBE_COUNT + ' 条不受影响'
}

async function loadHistory(): Promise<void> {
  const r = await M.listBundles()
  history.value = (r.bundles || []) as BundleMeta[]
}

async function openInResult(id: string): Promise<void> {
  const r = await M.useBundle(id)
  if (!r.ok) { ElMessage.error(r.hint || r.error || '打开失败'); return }
  await M.openResult()
  ElMessage.success('已在结果页打开该份采集')
}

async function removeOne(id: string): Promise<void> {
  const target = findInIndex(history.value, id)
  try {
    // 确认框里带上这份结果的摘要，删除时能看清删的是哪一次采集
    await ElMessageBox.confirm(`删除这份采集结果？
${target ? describeMeta(target) : id}

其完整数据会一并从本机移除，不可恢复。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  await M.deleteBundle(id)
  await loadHistory()
  ElMessage.success('已删除该条采集历史')
}

async function clearHistory(): Promise<void> {
  try {
    await ElMessageBox.confirm('清空全部采集历史，包括弹窗「查看结果」当前指向的那份。清空后需重新采集。', '清空确认', { type: 'warning', confirmButtonText: '清空全部', cancelButtonText: '取消' })
  } catch { return }
  await M.clearBundles()
  await loadHistory()
  ElMessage.success('已清空采集历史')
}

// 误报标记管理：结果页「标记误报」写入 chrome.storage.local.falsePositives（mapKey 字符串集合）。
// 此处在设置页集中查看/撤销/升全站；撤销只移除标记，原始 bundle 命中一律保留。
const fps = ref<string[]>([])
const fpRows = computed(() => fps.value.map((k) => ({ mapKey: k, ...describeFp(k) })))
const KIND_LABEL: Record<string, string> = { api: '敏感接口', probe: '主动探测', finding: '密钥命中', route: '路由' }
const kindLabel = (kind: string): string => KIND_LABEL[kind] || kind
function persistFps(): void {
  chrome.storage.local.set({ falsePositives: JSON.parse(JSON.stringify(fps.value)) })
}
function undoFp(mapKey: string): void {
  fps.value = withoutFp(fps.value, mapKey)
  persistFps()
  ElMessage.success('已撤销该误报标记')
}
function promoteFp(mapKey: string): void {
  const i = mapKey.indexOf('|')
  const sig = i < 0 ? mapKey : mapKey.slice(i + 1)
  fps.value = withFp(withoutFp(fps.value, mapKey), '*|' + sig)
  persistFps()
  ElMessage.success('已升级为全站标记，跨站点生效')
}
async function clearFps(): Promise<void> {
  try {
    await ElMessageBox.confirm('清空全部误报标记？原始命中数据不受影响，只是恢复全部展示。', '清空确认', { type: 'warning', confirmButtonText: '清空全部', cancelButtonText: '取消' })
  } catch { return }
  fps.value = []
  persistFps()
  ElMessage.success('已清空误报标记')
}

const fmt = (ts: number): string => new Date(ts).toLocaleString('zh-CN')

onMounted(async () => {
  const { scope, settings: s, falsePositives: fp } = await chrome.storage.local.get(['scope', 'settings', 'falsePositives'])
  if (scope && Array.isArray(scope.hosts)) hosts.value = scope.hosts
  Object.assign(settings, { ...DEFAULTS }, s || {})
  if (Array.isArray(fp)) fps.value = fp
  blacklistText.value = (settings.linkBlacklist || []).join('\n')
  applyTheme(resolveTheme(settings.theme))
  syncEffective()
  try {
    globalThis.matchMedia?.('(prefers-color-scheme: dark)').addEventListener?.('change', syncEffective)
  } catch { /* 无 matchMedia 的环境里静态显示即可 */ }
  patternText.value = JSON.stringify(toBackupPatterns(settings.userPatterns), null, 2)
  probeText.value = JSON.stringify(settings.userProbes, null, 2)
  // 历史列表要在页面打开时就拉一次，否则「采集历史」分区永远是空的
  await loadHistory()
})

async function persist(): Promise<void> {
  // 走 background 而不是直写存储：activeProbe 变化要同步重算常驻接管脚本的注册。
  // settings 是 reactive 深层代理，直接 {...settings} 展开出来的数组属性仍是 Proxy，
  // sendMessage 的 structuredClone 会抛 DataCloneError 并被消息层静默吞掉，导致保存看似成功实则没写进去。
  // 先序列化成纯数据快照再发，规避代理；并对失败给出提示，不再假装保存成功。
  const r = await M.setSettings(JSON.parse(JSON.stringify(settings)))
  if (!r.ok) ElMessage.error('设置保存失败，请重试')
}

async function changeTheme(id: ThemeId): Promise<void> {
  settings.theme = id
  applyTheme(id)
  syncEffective()
  await persist()
}

async function restoreDefaults(): Promise<void> {
  const keep = settings.theme
  Object.assign(settings, { ...DEFAULTS, theme: keep })
  blacklistText.value = ''
  await persist()
  ElMessage.success('已恢复默认参数')
}

</script>

<style scoped>
.opt { max-width: 860px; margin: 0 auto; padding: 30px 24px 56px; font: 14px/1.65 var(--rx-font); color: var(--rx-text); }

.head { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; flex-wrap: wrap; padding-bottom: 18px; margin-bottom: 26px; border-bottom: 1px solid var(--rx-border); }
h1 { margin: 0 0 7px; font-family: var(--rx-font-head); font-size: 20px; font-weight: 600; letter-spacing: .2px; color: var(--rx-accent); text-shadow: var(--rx-glow); }
.head-txt { flex: 1 1 380px; }
.sub { margin: 0; color: var(--rx-muted); font-size: 12.5px; max-width: 58ch; }
.chips { display: flex; gap: 7px; flex-wrap: wrap; padding-top: 3px; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; font-size: 11.5px; color: var(--rx-muted); background: var(--rx-bg-soft); border: 1px solid var(--rx-border); border-radius: 999px; }
.chip b { font-weight: 600; color: var(--rx-text); }
.chip.on { border-color: var(--rx-warn); }
.chip.on b { color: var(--rx-warn); }

.block { margin-bottom: 22px; }
.block-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; padding-left: 11px; margin-bottom: 9px; border-left: 2px solid var(--rx-accent); }
h2 { margin: 0; font-size: 13px; font-weight: 600; letter-spacing: .6px; color: var(--rx-text); }
.hint { color: var(--rx-muted); font-size: 11.5px; }

.theme-bar { display: flex; align-items: center; gap: 12px; padding: 9px 12px; background: var(--rx-bg-elev); border: 1px solid var(--rx-border); border-radius: 9px; }
.sw { display: inline-flex; width: 34px; height: 15px; flex: none; overflow: hidden; border-radius: 4px; border: 1px solid color-mix(in srgb, var(--rx-muted) 45%, transparent); }
.sw i { flex: 1; height: 100%; }
.tb-txt { display: flex; align-items: baseline; gap: 8px; min-width: 0; flex: 1; }
.tb-txt b { font-size: 13px; font-weight: 600; flex: none; }
.tb-txt em { font-style: normal; font-size: 11.5px; color: var(--rx-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tb-sel { width: 104px; flex: none; }
.tb-sel :deep(.el-input__wrapper) { background: var(--rx-bg-soft); }

.fields { background: var(--rx-bg-elev); border: 1px solid var(--rx-border); border-radius: 10px; padding: 2px 16px; }
.field { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 13px 0; border-bottom: 1px solid var(--rx-border); }
.field:last-of-type { border-bottom: none; }
.f-txt { min-width: 0; }
.f-txt b { display: block; font-size: 13px; font-weight: 600; margin-bottom: 3px; }
.f-txt p { margin: 0; font-size: 11.5px; line-height: 1.6; color: var(--rx-muted); }
.field.wide { flex-direction: column; align-items: stretch; gap: 9px; }
.field :deep(.el-input-number) { width: 112px; flex: none; }
.f-area { width: 100%; }
.foot-actions { display: flex; justify-content: flex-end; margin: 0 -16px; padding: 8px 16px; border-top: 1px solid var(--rx-border); }

.hosts {
  background: transparent;
  border: 1px solid var(--rx-border); border-radius: 10px; overflow: hidden;
  --el-table-bg-color: transparent; --el-table-tr-bg-color: transparent;
  --el-table-header-bg-color: var(--rx-bg-soft); --el-table-border-color: var(--rx-border);
  --el-table-text-color: var(--rx-text); --el-table-header-text-color: var(--rx-muted);
  --el-table-row-hover-bg-color: var(--rx-bg-soft);
}
.hosts :deep(th.el-table__cell) { font-size: 11.5px; font-weight: 500; letter-spacing: .5px; }
.host { font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 12.5px; color: var(--rx-text); }
.note { margin-left: 9px; font-size: 11.5px; color: var(--rx-muted); }
.empty { padding: 24px; text-align: center; color: var(--rx-muted); font-size: 12.5px; background: var(--rx-bg-elev); border: 1px dashed var(--rx-border); border-radius: 10px; }

.warn-bar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-top: 10px; padding: 11px 14px; background: var(--rx-bg-soft); border: 1px solid var(--rx-border); border-left: 2px solid var(--rx-danger); border-radius: 9px; }
.mono { font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 12px; color: var(--rx-muted); }
.hist-foot { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 10px; }
.bar-row { display: flex; align-items: center; gap: 8px; }
.rule-msg { display: block; margin-top: 10px; }
.w-txt b { display: block; font-size: 12.5px; font-weight: 600; margin-bottom: 2px; }
.w-txt p { margin: 0; font-size: 11.5px; color: var(--rx-muted); }

.legal { margin-top: 26px; padding-top: 16px; border-top: 1px solid var(--rx-border); font-size: 11.5px; line-height: 1.75; color: var(--rx-muted); }
code { font-size: 11.5px; background: var(--rx-code-bg); padding: 1px 5px; border-radius: 4px; }
</style>
