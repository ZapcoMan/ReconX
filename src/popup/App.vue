<template>
  <div class="pop">
    <div class="head">
      <span class="title">ReconX</span>
      <el-tag v-if="store.settings.activeProbe" type="warning" size="small">主动探测已开</el-tag>
      <el-button class="gear" text :icon="Setting" title="设置" @click="openOptions" />
    </div>

    <div class="host">{{ store.active.host || '（无可用页面）' }}</div>

    <el-space direction="vertical" fill class="acts" :size="8">
      <el-button type="primary" :disabled="!store.active.tabId" :loading="store.busyAction === 'collect'" @click="onCollect">开始采集</el-button>
      <el-button :disabled="!store.lastBundle || !store.settings.activeProbe" :loading="store.busyAction === 'probes'" @click="onProbes">主动探测</el-button>
      <el-button :disabled="!store.lastBundle" @click="store.openResult()">查看结果</el-button>
    </el-space>

    <p v-if="!store.settings.activeProbe" class="tip">主动探测已在设置页关闭：探测按钮与常驻接管脚本均未启用。</p>

    <el-alert v-if="store.message" :title="store.message" type="info" :closable="false" class="msg" />

    <div class="foot">仅用于已授权目标（渗透测试 / 漏洞赏金 / OSINT / 自查）。</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { Setting } from '@element-plus/icons-vue'
import { useAppStore } from '../stores/app'

const store = useAppStore()

onMounted(async () => {
  await store.refresh()
})

function openOptions(): void {
  chrome.runtime.openOptionsPage()
}
async function onCollect(): Promise<void> {
  await store.collect()
}
async function onProbes(): Promise<void> {
  await store.probes()
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
.host { margin: 8px 0 10px; color: var(--rx-muted); word-break: break-all; font-family: var(--rx-font); font-size: 12px; }
.acts { width: 100%; }
.acts :deep(.el-button) { width: 100%; margin-left: 0; }
.msg { margin-top: 10px; }
.tip { margin: 8px 0 0; color: var(--rx-muted); font-size: 11.5px; line-height: 1.5; }
.foot { margin-top: 12px; color: var(--rx-muted); font-size: 11px; }
</style>