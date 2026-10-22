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
        <span class="sw"><i v-for="(c, i) in themeMeta.swatch" :key="i" :style="{ background: c }"></i></span>
        <span class="tb-txt"><b>{{ themeMeta.label }}</b><em>{{ themeMeta.desc }}</em></span>
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
      <div class="block-head"><h2>允许域</h2><span class="hint">只有列在这里的主机可被采集与探测</span></div>
      <el-table v-if="hosts.length" :data="hosts" size="small" class="hosts">
        <el-table-column label="主机">
          <template #default="{ row }"><span class="host">{{ row.host }}</span><span v-if="row.note" class="note">{{ row.note }}</span></template>
        </el-table-column>
        <el-table-column label="加入时间" width="150" class-name="mono"><template #default="{ row }">{{ fmt(row.addedAt) }}</template></el-table-column>
        <el-table-column label="" width="72" align="right"><template #default="{ row }"><el-button size="small" text type="danger" @click="remove(row.host, row.origin)">移除</el-button></template></el-table-column>
      </el-table>
      <div v-else class="empty">尚无允许域。打开目标站点，点扩展图标里的「授权并加入范围」即可添加。</div>
      <div class="warn-bar">
        <div class="w-txt"><b>撤销全部主机权限</b><p>移除扩展已获得的全部站点访问权限。关闭「启用主动探测」会同时注销常驻接管脚本。</p></div>
        <el-button size="small" type="danger" plain @click="revokeAll">撤销全部</el-button>
      </div>
    </section>

    <footer class="legal">
      ReconX 仅用于你拥有或已获书面授权的目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。命中皆为线索，需人工确认，且一律以原文留存并进入导出文件。所有数据仅保存在本机浏览器，不外传。请遵守目标站点条款与当地法律。
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as M from '../shared/messaging'
import type { ScopeHost, Settings } from '../types'
import { THEME_ORDER, THEME_META, type ThemeId } from '../core/themes'
import { applyTheme, resolveTheme } from '../shared/theme'

const DEFAULTS: Settings = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark', linkBlacklist: [] }

const hosts = ref<ScopeHost[]>([])
const settings = reactive<Settings>({ ...DEFAULTS })
// 黑名单在设置里是 string[]，界面用多行文本编辑，两者在此互转
const blacklistText = ref('')
const themeMeta = computed(() => THEME_META[settings.theme] || THEME_META.dark)

function applyBlacklist(): Promise<void> {
  settings.linkBlacklist = blacklistText.value.split('\n').map((s) => s.trim()).filter(Boolean)
  return persist()
}

const fmt = (ts: number): string => new Date(ts).toLocaleString('zh-CN')

onMounted(async () => {
  const { scope, settings: s } = await chrome.storage.local.get(['scope', 'settings'])
  if (scope && Array.isArray(scope.hosts)) hosts.value = scope.hosts
  Object.assign(settings, { ...DEFAULTS }, s || {})
  blacklistText.value = (settings.linkBlacklist || []).join('\n')
  applyTheme(resolveTheme(settings.theme))
})

async function persist(): Promise<void> {
  // 走 background 而不是直写存储：activeProbe 变化要同步重算常驻接管脚本的注册
  await M.setSettings({ ...settings })
}

async function changeTheme(id: ThemeId): Promise<void> {
  settings.theme = id
  applyTheme(id)
  await persist()
}

async function restoreDefaults(): Promise<void> {
  const keep = settings.theme
  Object.assign(settings, { ...DEFAULTS, theme: keep })
  blacklistText.value = ''
  await persist()
  ElMessage.success('已恢复默认参数')
}

async function remove(host: string, origin: string): Promise<void> {
  try {
    await ElMessageBox.confirm(`将移除 ${host}，并撤销该站点的访问权限。`, '移除确认', { type: 'warning', confirmButtonText: '移除', cancelButtonText: '取消' })
  } catch { return }
  // 走 background 消息路径，让允许域变更与常驻脚本注册保持同步
  await M.removeHost(host, origin)
  const { scope } = await chrome.storage.local.get('scope')
  hosts.value = scope && Array.isArray(scope.hosts) ? scope.hosts : []
  ElMessage.success('已移除 ' + host)
}

async function revokeAll(): Promise<void> {
  try {
    await ElMessageBox.confirm('将撤销扩展已获得的全部站点访问权限。', '撤销确认', { type: 'warning', confirmButtonText: '撤销全部', cancelButtonText: '取消' })
  } catch { return }
  try {
    const all = await chrome.permissions.getAll()
    if (all.origins && all.origins.length) {
      await chrome.permissions.remove({ origins: all.origins })
      ElMessage.success('已撤销 ' + all.origins.length + ' 个 host 权限')
    } else {
      ElMessage.info('当前没有已授予的 host 权限')
    }
  } catch (e: any) {
    ElMessage.error('撤销失败：' + String((e && e.message) || e))
  }
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
.w-txt b { display: block; font-size: 12.5px; font-weight: 600; margin-bottom: 2px; }
.w-txt p { margin: 0; font-size: 11.5px; color: var(--rx-muted); }

.legal { margin-top: 26px; padding-top: 16px; border-top: 1px solid var(--rx-border); font-size: 11.5px; line-height: 1.75; color: var(--rx-muted); }
code { font-size: 11.5px; background: var(--rx-code-bg); padding: 1px 5px; border-radius: 4px; }
</style>
