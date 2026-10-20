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

function injectableScriptsPlugin(): Plugin {
  return {
    name: 'reconx:injectable-scripts',
    apply: 'build',
    async buildStart() {
      await buildAllIn()
      await buildDetector()
      await buildApiExtractor()
    }
  }
}

const manifest = defineManifest({
  manifest_version: 3,
  name: 'ReconX - 授权范围信息收集',
  version: '0.2.0',
  description:
    '面向已授权目标（渗透测试/漏洞赏金/OSINT/自查）的浏览器侦察助手：技术栈与WAF指纹、响应头与Cookie分析、JS敏感信息扫描、链接与参数收集、只读前端路由枚举。内置允许域范围管控。',
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
  optional_host_permissions: ['<all_urls>'],
  host_permissions: [],
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
      run_at: 'document_idle'
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
    injectableScriptsPlugin()
  ],
  build: {
    sourcemap: true,
    rollupOptions: {
      input: { result: 'src/result/result.html' }
    }
  }
})