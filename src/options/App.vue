<template>
  <div class="opt">
    <h1>ReconX 设置与范围管理</h1>

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

const hosts = ref<ScopeHost[]>([])
const settings = reactive<Settings>({ activeProbe: false, maxJsFiles: 25, maxConcurrent: 5 })

onMounted(async () => {
  const { scope, settings: s } = await chrome.storage.local.get(['scope', 'settings'])
  if (scope && Array.isArray(scope.hosts)) hosts.value = scope.hosts
  Object.assign(settings, { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5 }, s || {})
})

async function remove(row: any): Promise<void> {
  const next = hosts.value.filter((h) => h.host !== row.host)
  hosts.value = next
  await chrome.storage.local.set({ scope: { hosts: next } })
  try { if (row.origin) await chrome.permissions.remove({ origins: [row.origin + '/*'] }) } catch { /* */ }
  ElMessage.success('已移除 ' + row.host)
}

async function save(): Promise<void> {
  await chrome.storage.local.set({ settings: { ...settings } })
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
.opt { max-width: 880px; margin: 0 auto; padding: 28px 24px 60px; font: 14px/1.6 system-ui, 'Microsoft YaHei', sans-serif; color: #1f2937; }
h1 { font-size: 20px; color: #0d9488; }
h2 { font-size: 15px; margin: 22px 0 10px; border-left: 3px solid #0d9488; padding-left: 8px; }
section { margin-bottom: 18px; }
.note { color: #64748b; font-size: 13px; background: #f1f5f9; padding: 12px 14px; border-radius: 8px; }
</style>
