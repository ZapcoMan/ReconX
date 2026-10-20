<template>
  <div class="pop">
    <div class="head">
      <span class="title">ReconX</span>
      <el-tag v-if="store.inScope" type="success" size="small">在允许域</el-tag>
      <el-tag v-else type="danger" size="small">未授权</el-tag>
      <el-button class="gear" text :icon="Setting" title="设置" @click="openOptions" />
    </div>

    <div class="themebrew">
      <el-segmented v-model="themeId" :options="themeOptions" size="small" @change="onTheme" />
    </div>

    <div class="host">{{ store.active.host || '（无可用页面）' }}</div>

    <el-space direction="vertical" fill class="acts" :size="8">
      <el-button v-if="!store.inScope" type="primary" :loading="store.busy" @click="onAuthorize">授权并加入范围</el-button>
      <el-button :disabled="!store.inScope" :loading="store.busy" @click="onCollect">采集当前页</el-button>
      <el-button :disabled="!store.inScope || !store.lastBundle" :loading="store.busy" @click="onProbes">主动探测</el-button>
      <el-button :disabled="!store.lastBundle" @click="store.openResult()">查看结果</el-button>
      <el-dropdown :disabled="!store.lastBundle" trigger="click" @command="onExport">
        <el-button :disabled="!store.lastBundle">导出<el-icon><ArrowDown /></el-icon></el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="json">JSON</el-dropdown-item>
            <el-dropdown-item command="csv">CSV</el-dropdown-item>
            <el-dropdown-item command="md">Markdown 报告</el-dropdown-item>
            <el-dropdown-item command="src">SRC 提交草稿</el-dropdown-item>
            <el-dropdown-item command="html">HTML 报告</el-dropdown-item>
            <el-dropdown-item command="txt">端点 TXT</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </el-space>

    <el-alert v-if="store.message" :title="store.message" type="info" :closable="false" class="msg" />

    <div class="foot">仅用于已授权目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Setting, ArrowDown } from '@element-plus/icons-vue'
import { useAppStore } from '../stores/app'
import { exportBundle } from '../core/exporter'
import { THEME_ORDER, THEME_META, type ThemeId } from '../core/themes'

const store = useAppStore()
const themeId = ref<ThemeId>(store.settings.theme)
const themeOptions = THEME_ORDER.map((id) => ({ label: THEME_META[id].label, value: id }))

onMounted(async () => {
  await store.refresh()
  themeId.value = store.settings.theme
})

function openOptions(): void {
  chrome.runtime.openOptionsPage()
}
async function onAuthorize(): Promise<void> {
  await store.authorize()
}
async function onCollect(): Promise<void> {
  await store.collect()
}
async function onProbes(): Promise<void> {
  await store.probes()
}
function onExport(fmt: string): void {
  if (store.lastBundle) exportBundle(store.lastBundle, fmt)
}
async function onTheme(val: ThemeId): Promise<void> {
  await store.setTheme(val)
}
</script>

<style scoped>
.pop {
  width: 340px;
  padding: 12px 14px 14px;
  font: 13px/1.5 var(--rx-font);
  color: var(--rx-text);
  background: var(--rx-bg);
  min-height: 100%;
}
.head { display: flex; align-items: center; gap: 8px; }
.title { font-family: var(--rx-font-head); font-weight: 700; font-size: 15px; color: var(--rx-accent); text-shadow: var(--rx-glow); }
.gear { margin-left: auto; }
.themebrew { margin: 8px 0 2px; }
.host { margin: 6px 0 10px; color: var(--rx-muted); word-break: break-all; font-family: var(--rx-font); font-size: 12px; }
.acts { width: 100%; }
.acts :deep(.el-button) { width: 100%; margin-left: 0; }
.msg { margin-top: 10px; }
.foot { margin-top: 12px; color: var(--rx-muted); font-size: 11px; }
</style>
