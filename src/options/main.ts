import { createApp } from 'vue'
import { createPinia } from 'pinia'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import App from './App.vue'
import { applyTheme } from '../shared/theme'
import { DEFAULT_THEME } from '../core/themes'

applyTheme(DEFAULT_THEME)
createApp(App).use(createPinia()).mount('#app')
