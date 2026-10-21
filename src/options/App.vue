<template>
  <div class="opt">
    <header class="page-head">
      <div>
        <h1>设置与范围管理</h1>
        <p class="sub">允许域决定 ReconX 能在哪些主机上工作；采集参数与主动探测开关决定它做多少事。</p>
      </div>
      <div class="head-stat">
        <div class="stat"><b>{{ hosts.length }}</b><span>允许域</span></div>
        <div class="stat"><b :class="{ on: settings.activeProbe }">{{ settings.activeProbe ? '已开启' : '已关闭' }}</b><span>主动探测</span></div>
      </div>
    </header>

    <div class="layout">
      <section class="card">
        <div class="card-head"><h2>外观主题</h2><span class="hint">即时生效并记住</span></div>
        <div class="themes">
          <button
            v-for="id in THEME_ORDER" :key="id" type="button"
            class="theme-card" :class="{ active: settings.theme === id }"
            @click="changeTheme(id)"
          >
            <span class="dots"><i v-for="(c, i) in THEME_META[id].swatch" :key="i" :style="{ background: c }"></i></span>
            <b>{{ THEME_META[id].label }}</b>
            <span class="desc">{{ THEME_META[id].desc }}</span>
            <span v-if="settings.theme === id" class="tick">使用中</span>
          </button>
        </div>
      </section>

      <section class="card">
        <div class="card-head"><h2>采集参数</h2><span class="hint">修改即时保存</span></div>
        <div class="rows">
          <label class="row switch-row">
            <span class="lbl">启用主动探测</span>
            <el-switch v-model="settings.activeProbe" @change="persist" />
          </label>
          <p class="desc">开启后才允许执行敏感路径与路由可达性探测，并把常驻接管脚本注册到允许域；关闭时弹窗的探测按钮不可用，已注册的脚本会被撤销。</p>

          <label class="row">
            <span class="lbl">最多扫描 JS 文件数</span>
            <el-input-number v-model="settings.maxJsFiles" :min="1" :max="200" size="small" @change="persist" />
          </label>
          <p class="desc">单次采集拉取并分析的外链脚本上限，越大越慢、越容易碰到跨域失败。</p>

          <label class="row">
            <span class="lbl">并发抓取数</span>
            <el-input-number v-model="settings.maxConcurrent" :min="1" :max="12" size="small" @change="persist" />
          </label>
          <p class="desc">同时向目标拉取 JS 的请求数，调高会明显增加目标负载。</p>

          <div class="row action-row">
            <el-button size="small" text @click="restoreDefaults">恢复默认参数</el-button>
          </div>
        </div>
      </section>

      <section class="card wide">
        <div class="card-head"><h2>允许域</h2><span class="hint">只有列在这里的主机可被采集与探测</span></div>
        <el-table v-if="hosts.length" :data="hosts" size="small">
          <el-table-column prop="host" label="主机"><template #default="{ row }"><code>{{ row.host }}</code></template></el-table-column>
          <el-table-column prop="origin" label="来源"><template #default="{ row }"><code>{{ row.origin }}</code></template></el-table-column>
          <el-table-column prop="note" label="备注" width="160" />
          <el-table-column label="加入时间" width="180"><template #default="{ row }">{{ fmt(row.addedAt) }}</template></el-table-column>
          <el-table-column label="操作" width="90"><template #default="{ row }"><el-button size="small" type="danger" text @click="remove(row.host, row.origin)">移除</el-button></template></el-table-column>
        </el-table>
        <div v-else class="empty">尚无允许域。打开目标站点，点扩展图标里的「授权并加入范围」即可添加。</div>
        <div class="danger-zone">
          <div>
            <b>撤销全部主机权限</b>
            <p class="desc">移除扩展已获得的站点访问权限。关闭上方的主动探测开关会同时注销常驻接管脚本。</p>
          </div>
          <el-button size="small" type="danger" plain @click="revokeAll">撤销全部</el-button>
        </div>
      </section>

      <section class="card wide note-card">
        <h2>合规声明</h2>
        <p>ReconX 仅用于你拥有或已获书面授权的目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。命中皆为线索，需人工确认。所有数据仅保存在本地浏览器，不外传。请遵守目标站点条款与当地法律。</p>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as M from '../shared/messaging'
import type { ScopeHost, Settings } from '../types'
import { THEME_ORDER, THEME_META, type ThemeId } from '../core/themes'
import { applyTheme, resolveTheme } from '../shared/theme'

const DEFAULTS: Settings = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark' }

const hosts = ref<ScopeHost[]>([])
const settings = reactive<Settings>({ ...DEFAULTS })

const fmt = (ts: number): string => new Date(ts).toLocaleString('zh-CN')

onMounted(async () => {
  const { scope, settings: s } = await chrome.storage.local.get(['scope', 'settings'])
  if (scope && Array.isArray(scope.hosts)) hosts.value = scope.hosts
  Object.assign(settings, { ...DEFAULTS }, s || {})
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
.opt { max-width: 1040px; margin: 0 auto; padding: 26px 22px 60px; font: 14px/1.65 var(--rx-font); color: var(--rx-text); }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; flex-wrap: wrap; padding-bottom: 16px; border-bottom: 1px solid var(--rx-border); }
h1 { margin: 0 0 6px; font-family: var(--rx-font-head); font-size: 21px; color: var(--rx-accent); text-shadow: var(--rx-glow); }
.sub { margin: 0; color: var(--rx-muted); font-size: 13px; max-width: 62ch; }
.head-stat { display: flex; gap: 10px; }
.stat { min-width: 96px; padding: 8px 14px; background: var(--rx-bg-elev); border: 1px solid var(--rx-border); border-radius: 8px; display: flex; flex-direction: column; }
.stat b { font-size: 16px; color: var(--rx-accent); }
.stat b.on { color: var(--rx-warn); }
.stat span { font-size: 11.5px; color: var(--rx-muted); }
.layout { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; margin-top: 20px; align-items: start; }
.card { background: var(--rx-bg-elev); border: 1px solid var(--rx-border); border-radius: 12px; padding: 16px 18px 18px; }
.card.wide { grid-column: 1 / -1; }
.card-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
h2 { margin: 0; font-size: 14.5px; letter-spacing: .3px; }
.hint { color: var(--rx-muted); font-size: 12px; }
.desc { margin: 0 0 12px; color: var(--rx-muted); font-size: 12px; line-height: 1.55; }

.themes { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.theme-card { position: relative; text-align: left; cursor: pointer; padding: 12px; border-radius: 10px; border: 1px solid var(--rx-border); background: var(--rx-bg-soft); color: var(--rx-text); font: inherit; display: flex; flex-direction: column; gap: 6px; }
.theme-card:hover { border-color: var(--rx-accent); }
.theme-card.active { border-color: var(--rx-accent); box-shadow: 0 0 0 1px var(--rx-accent) inset; }
.theme-card b { font-size: 13.5px; }
.theme-card .desc { margin: 0; }
.dots { display: inline-flex; gap: 4px; }
.dots i { width: 14px; height: 14px; border-radius: 50%; border: 1px solid var(--rx-border); }
.tick { position: absolute; top: 10px; right: 10px; font-size: 10.5px; background: var(--rx-accent); color: var(--rx-accent-contrast); padding: 1px 7px; border-radius: 999px; }

.rows { display: flex; flex-direction: column; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 4px; }
.row .lbl { font-size: 13.5px; }
.action-row { justify-content: flex-start; margin-top: 6px; }

.empty { padding: 26px; text-align: center; color: var(--rx-muted); border: 1px dashed var(--rx-border); border-radius: 10px; font-size: 13px; }
code { font-size: 12.5px; background: var(--rx-code-bg); padding: 1px 6px; border-radius: 4px; }

.danger-zone { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 16px; padding: 12px 14px; border: 1px solid var(--rx-border); border-left: 3px solid var(--rx-danger); border-radius: 8px; background: var(--rx-bg-soft); }
.danger-zone b { font-size: 13.5px; }
.danger-zone .desc { margin: 2px 0 0; }

.note-card { color: var(--rx-muted); font-size: 13px; line-height: 1.7; }
.note-card h2 { color: var(--rx-text); margin-bottom: 8px; }
.note-card p { margin: 0; }
</style>
