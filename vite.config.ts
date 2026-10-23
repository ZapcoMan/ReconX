import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'
import { crx, defineManifest } from '@crxjs/vite-plugin'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
import { fileURLToPath, URL } from 'node:url'
import path from 'node:path'

const ROOT = fileURLToPath(new URL('.', import.meta.url))
const DIST = path.join(ROOT, 'dist')
const PUBLIC = path.join(ROOT, 'public')

function stripUseStrictPlugin(): Plugin {
  return {
    name: 'reconx:strip-use-strict',
    enforce: 'post',
    renderChunk(code: string) {
      const stripped = code.replace(/\n\s*["']use strict["'];\n/, '\n')
      return stripped === code ? null : { code: stripped, map: null }
    }
  }
}

async function buildAllIn(): Promise<void> {
  const { build } = await import('vite')
  await build({
    configFile: false,
    publicDir: false,
    logLevel: 'warn',
    plugins: [stripUseStrictPlugin()],
    build: {
      outDir: PUBLIC,
      emptyOutDir: false,
      minify: false,
      target: 'chrome110',
      rollupOptions: {
        treeshake: false,
        input: path.join(ROOT, 'src', 'core', 'all-in.ts'),
        output: {
          format: 'iife',
          entryFileNames: 'all-in.js'
        }
      }
    }
  })
}

async function buildDetector(): Promise<void> {
  const { build } = await import('vite')
  await build({
    configFile: false,
    publicDir: false,
    logLevel: 'warn',
    plugins: [stripUseStrictPlugin()],
    build: {
      outDir: PUBLIC,
      emptyOutDir: false,
      minify: false,
      target: 'chrome110',
      rollupOptions: {
        treeshake: false,
        input: path.join(ROOT, 'src', 'core', 'detector.ts'),
        output: {
          format: 'iife',
          entryFileNames: 'detector.js'
        }
      }
    }
  })
}

async function buildApiExtractor(): Promise<void> {
  const { build } = await import('vite')
  await build({
    configFile: false,
    publicDir: false,
    logLevel: 'warn',
    plugins: [stripUseStrictPlugin()],
    build: {
      outDir: PUBLIC,
      emptyOutDir: false,
      minify: false,
      target: 'chrome110',
      rollupOptions: {
        treeshake: false,
        input: path.join(ROOT, 'src', 'core', 'api-extractor.ts'),
        output: {
          format: 'iife',
          entryFileNames: 'api-extractor.js'
        }
      }
    }
  })
}

function copyToDistPlugin(): Plugin {
  return {
    name: 'reconx:copy-to-dist',
    apply: 'build',
    async closeBundle() {
      const fs = await import('node:fs')
      const scripts = ['all-in.js', 'detector.js', 'api-extractor.js']
      for (const script of scripts) {
        const src = path.join(PUBLIC, script)
        const dest = path.join(DIST, script)
        if (fs.existsSync(src)) {
          fs.copyFileSync(src, dest)
        }
      }
    }
  }
}

// 在 Vite 配置加载前预先构建独立脚本，确保 CRX 插件能找到它们
;(async () => {
  await buildAllIn()
  await buildDetector()
  await buildApiExtractor()
})()

const manifest = defineManifest({
  manifest_version: 3,
  name: 'ReconX - 前端资产与授权侦察',
  version: '1.6.6',
  description:
    '已授权目标的浏览器侦察工作台：技术栈/WAF 指纹、响应头与 Cookie 分析、JS 敏感信息扫描、链接与参数收集、前端路由与 API 枚举；主动探测含客户端路由接管（不绕过服务端鉴权）。作用范围由使用者负责。',
  action: {
    default_popup: 'src/popup/popup.html',
    default_title: 'ReconX',
    default_icon: { '16': 'icons/icon16.png', '48': 'icons/icon48.png', '128': 'icons/icon128.png' }
  },
  icons: { '16': 'icons/icon16.png', '48': 'icons/icon48.png', '128': 'icons/icon128.png' },
  background: { service_worker: 'src/background.ts', type: 'module' },
  options_page: 'src/options/options.html',
  permissions: ['tabs', 'scripting', 'storage', 'webRequest'],
  optional_permissions: [],
  // 1.0.0 起去掉逐 host 授权：静态申请全站 host 权限，采集/探测/接管不再受允许域范围限制。
  // 合规责任转由使用者承担（见 README/官网的授权须知）。
  host_permissions: ['<all_urls>'],
  web_accessible_resources: [
    {
      resources: ['src/result/result.html', 'all-in.js', 'detector.js', 'api-extractor.js'],
      matches: ['<all_urls>']
    }
  ],
  content_scripts: [
    {
      matches: ['<all_urls>'],
      js: ['src/extension/content.ts'],
      run_at: 'document_start',
      all_frames: true
    }
  ],
  content_security_policy: { extension_pages: "script-src 'self'; object-src 'self'" }
})

export default defineConfig({
  plugins: [
    vue(),
    AutoImport({ resolvers: [ElementPlusResolver()] }),
    Components({ resolvers: [ElementPlusResolver()] }),
    crx({ manifest }),
    copyToDistPlugin()
  ],
  build: {
    sourcemap: true,
    rollupOptions: {
      input: { result: 'src/result/result.html' }
    }
  }
})