<template>
  <div class="opt">
    <h1>ReconX 设置与范围管理</h1>

    <section>
      <h2>外观主题</h2>
      <div class="theme-row">
        <el-segmented v-model="theme" :options="themeOptions" @change="changeTheme" />
      </div>
      <div class="swatches">
        <div v-for="id in THEME_ORDER" :key="id" class="swatch">
          <span class="dots"><i v-for="(c, i) in THEME_META[id].swatch" :key="i" :style="{ background: c }"></i></span>
          <b>{{ THEME_META[id].label }}</b>
          <span class="desc">{{ THEME_META[id].desc }}</span>
        </div>
      </div>
    </section>

    <section>
      <h2>允许域（仅这些主机可采集/探测）</h2>
      <el-table :data="hosts" size="small" empty-text="尚无允许域，请在弹窗对目标页点“授权并加入范围”">
        <el-table-column prop="host" label="主机" />
        <el-table-column prop="origin" label="来源" />
        <el-table-column prop="note" label="备注" />
        <el-table-column label="加入时间" width="180"><template #default="{ row }">{{ new Date(row.addedAt).toLocaleString('zh-CN') }}</template></el-table-column>
        <el-table-column label="操作" width="90"><template #default="{ row }"><el-button size="small" type="danger" text @click="remove(row)">移除</el-button></template></el-table-column>
      </el-table>
      <el-button size="small" type="warning" plain @click="revokeAll">撤销全部 host 权限</el-button>
    </section>

    <section>
      <h2>采集参数</h2>
      <el-form label-width="160px">
        <el-form-item label="默认执行主动探测"><el-switch v-model="settings.activeProbe" /></el-form-item>
        <el-form-item label="最多扫描 JS 文件数"><el-input-number v-model="settings.maxJsFiles" :min="1" :max="200" /></el-form-item>
        <el-form-item label="并发抓取数"><el-input-number v-model="settings.maxConcurrent" :min="1" :max="12" /></el-form-item>
        <el-form-item><el-button type="primary" @click="save">保存设置</el-button></el-form-item>
      </el-form>
    </section>

    <section>
      <h2>合规声明</h2>
      <p class="note">ReconX 仅用于你拥有或已获书面授权的目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。命中皆为线索，需人工确认。所有数据仅保存在本地浏览器，不外传。请遵守目标站点条款与当地法律。</p>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import type { ScopeHost, Settings } from '../types'
import { THEME_ORDER, THEME_META, type ThemeId } from '../core/themes'
import { applyTheme, resolveTheme } from '../shared/theme'

const hosts = ref<ScopeHost[]>([])
const settings = reactive<Settings>({ activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark' })
const theme = ref<ThemeId>('dark')
const themeOptions = THEME_ORDER.map((id) => ({ label: THEME_META[id].label, value: id }))

onMounted(async () => {
  const { scope, settings: s } = await chrome.storage.local.get(['scope', 'settings'])
  if (scope && Array.isArray(scope.hosts)) hosts.value = scope.hosts
  Object.assign(settings, { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark' }, s || {})
  theme.value = resolveTheme(settings.theme)
  applyTheme(theme.value)
})

async function persist(): Promise<void> {
  await chrome.storage.local.set({ settings: { ...settings } })
}

function changeTheme(id: ThemeId): void {
  settings.theme = id
  applyTheme(id)
  void persist()
}

async function remove(row: any): Promise<void> {
  const next = hosts.value.filter((h) => h.host !== row.host)
  hosts.value = next
  await chrome.storage.local.set({ scope: { hosts: next } })
  try { if (row.origin) await chrome.permissions.remove({ origins: [row.origin + '/*'] }) } catch { /* */ }
  ElMessage.success('已移除 ' + row.host)
}

async function save(): Promise<void> {
  await persist()
  ElMessage.success('设置已保存')
}

async function revokeAll(): Promise<void> {
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
.opt { max-width: 880px; margin: 0 auto; padding: 28px 24px 60px; font: 14px/1.6 var(--rx-font); color: var(--rx-text); }
h1 { font-family: var(--rx-font-head); font-size: 20px; color: var(--rx-accent); text-shadow: var(--rx-glow); }
h2 { font-size: 15px; margin: 22px 0 10px; border-left: 3px solid var(--rx-accent); padding-left: 8px; }
section { margin-bottom: 18px; }
.theme-row { margin-bottom: 10px; }
.swatches { display: flex; flex-wrap: wrap; gap: 14px; }
.swatch { display: flex; flex-direction: column; gap: 4px; padding: 8px 12px; background: var(--rx-bg-elev); border: 1px solid var(--rx-border); border-radius: 8px; min-width: 180px; }
.swatch .desc { color: var(--rx-muted); font-size: 12px; }
.dots { display: inline-flex; gap: 4px; }
.dots i { width: 14px; height: 14px; border-radius: 50%; border: 1px solid var(--rx-border); }
.note { color: var(--rx-muted); font-size: 13px; background: var(--rx-bg-soft); padding: 12px 14px; border-radius: 8px; border: 1px solid var(--rx-border); }
</style>
