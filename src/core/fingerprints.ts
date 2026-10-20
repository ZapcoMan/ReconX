// 技术栈 / WAF / 服务器 / CDN / 版本 指纹规则库（自 lib/fingerprints.js 迁移为 ES 模块）
import type { PatternRule, GlobalVarProbe, WafRule } from '../types'

export function versionFrom(str: string | null | undefined): string | null {
  if (!str) return null
  const m = String(str).match(/v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)/)
  return m ? m[1] : null
}

export const SERVER_TECH: PatternRule[] = [
  { re: /nginx/i, name: 'nginx' },
  { re: /openresty/i, name: 'OpenResty' },
  { re: /tengine/i, name: 'Tengine (阿里)' },
  { re: /Apache/i, name: 'Apache HTTP Server' },
  { re: /Microsoft-?IIS|IIS\/|Windows-Server/i, name: 'Microsoft IIS' },
  { re: /LiteSpeed/i, name: 'LiteSpeed' },
  { re: /caddy/i, name: 'Caddy' },
  { re: /gunicorn/i, name: 'gunicorn (Python)' },
  { re: /uWSGI/i, name: 'uWSGI' },
  { re: /jetty/i, name: 'Eclipse Jetty' },
  { re: /Tomcat|Coyote/i, name: 'Apache Tomcat' },
  { re: /Varnish/i, name: 'Varnish Cache' },
  { re: /ATS|Apache Traffic Server/i, name: 'Apache Traffic Server' },
  { re: /SAP NetWeaver|SAP/i, name: 'SAP NetWeaver' },
  { re: /Zen|Zen\+\+/i, name: 'Zen load balancer' }
]

export const POWERED_BY: PatternRule[] = [
  { re: /PHP/i, name: 'PHP' },
  { re: /ASP\.NET/i, name: 'ASP.NET' },
  { re: /Express/i, name: 'Express (Node.js)' },
  { re: / Servlet/i, name: 'Java Servlet' }
]

export const GENERATOR: PatternRule[] = [
  { re: /WordPress/i, name: 'WordPress' },
  { re: /Joomla/i, name: 'Joomla' },
  { re: /Drupal/i, name: 'Drupal' },
  { re: /Wix/i, name: 'Wix' },
  { re: /Squarespace/i, name: 'Squarespace' },
  { re: /Weebly/i, name: 'Weebly' },
  { re: /Ghost/i, name: 'Ghost' },
  { re: /Hugo/i, name: 'Hugo' },
  { re: /Jekyll/i, name: 'Jekyll' },
  { re: /Webflow/i, name: 'Webflow' },
  { re: /Docusaurus/i, name: 'Docusaurus' },
  { re: /Shopify/i, name: 'Shopify' },
  { re: /Movable ?Type|MT/i, name: 'Movable Type' }
]

export const COOKIE_TECH: PatternRule[] = [
  { re: /^(wordpress|wp-|woocommerce)/i, name: 'WordPress' },
  { re: /^PHPSESSID$/i, name: 'PHP (会话)' },
  { re: /^JSESSIONID$/i, name: 'Java / Servlet 容器' },
  { re: /^(ASP\.NET_SessionId|\.AspNet|ASPXAUTH|ARRAffinity)/i, name: 'ASP.NET' },
  { re: /^(laravel_session|XSRF-TOKEN|remember_web_)/i, name: 'Laravel' },
  { re: /^(ci_session|csrf_test_name)/i, name: 'CodeIgniter' },
  { re: /^(SFSYMFOS|symfony)/i, name: 'Symfony' },
  { re: /^_session_id$/i, name: 'Ruby on Rails' },
  { re: /^(SESS[0-9a-f]{8,}|has_js|drupal)/i, name: 'Drupal' },
  { re: /^(connect\.sid|express\.sess|sid)/i, name: 'Express / Node.js' },
  { re: /django|csrftoken/i, name: 'Django' },
  { re: /magnento|mage|mage-cache/i, name: 'Magento' },
  { re: /^cake/i, name: 'CakePHP' }
]

export const URL_LIB_PATTERNS: PatternRule[] = [
  { re: /jquery[.-]?(\d[\d.]*)?(\.min)?\.js/i, name: 'jQuery' },
  { re: /zepto/i, name: 'Zepto' },
  { re: /bootstrap(\.min)?(\d[\d.]*)?\.js|\/bootstrap\//i, name: 'Bootstrap' },
  { re: /vue(\.runtime|\.global)?(\.prod)?(\.min)?\.js|\/vue\//i, name: 'Vue' },
  { re: /react-dom[\w.]*\.js|react[\w.]*\.min\.js|\/react\//i, name: 'React' },
  { re: /\/_next\/|__NEXT_DATA__|next\/(\d[\d.]*)/i, name: 'Next.js' },
  { re: /\/_nuxt\/|nuxt(\.min)?\.js/i, name: 'Nuxt.js' },
  { re: /chunk-vendors/i, name: 'Vue (webpack 打包)' },
  { re: /angular([\w.-]*)\.js|\/angular\//i, name: 'AngularJS/Angular' },
  { re: /svelte/i, name: 'Svelte' },
  { re: /lodash(\.min)?\.js/i, name: 'lodash' },
  { re: /moment(\.min)?\.js/i, name: 'Moment.js' },
  { re: /axios(\.min)?\.js/i, name: 'Axios' },
  { re: /three(\.min)?\.js/i, name: 'Three.js' },
  { re: /d3(\.v\d)?(\.min)?\.js/i, name: 'D3' },
  { re: /highcharts/i, name: 'Highcharts' },
  { re: /echarts/i, name: 'Apache ECharts' },
  { re: /chart\.?(\.min)?\.js|chartjs/i, name: 'Chart.js' },
  { re: /tinymce/i, name: 'TinyMCE' },
  { re: /ckeditor/i, name: 'CKEditor' },
  { re: /swiper/i, name: 'Swiper' },
  { re: /gsap|greensock/i, name: 'GSAP' },
  { re: /modernizr/i, name: 'Modernizr' },
  { re: /socket\.?io/i, name: 'Socket.IO' },
  { re: /firebase|firestore/i, name: 'Firebase' },
  { re: /sentry|browser[\w.]*bundle\.min\.js/i, name: 'Sentry' },
  { re: /\/wp-content\/|\/wp-includes\/|\/wp-json\//i, name: 'WordPress' },
  { re: /\/sites\/all\/|\/sites\/default\/|\/core\/misc\//i, name: 'Drupal' },
  { re: /joomla|\/media\/jui\//i, name: 'Joomla' },
  { re: /magento|\/static\/frontend\//i, name: 'Magento' },
  { re: /shopify|cdn\.shopify|\/shopify\//i, name: 'Shopify' },
  { re: /wixstatic|parastorage/i, name: 'Wix' },
  { re: /elementor/i, name: 'Elementor (WordPress)' },
  { re: /tailwind/i, name: 'Tailwind CSS' },
  { re: /google-analytics\.com\/ga\.js|\/gtag\/js|gtag(\.min)?\.js/i, name: 'Google Analytics/GTag' },
  { re: /googletagmanager\.com|\/gtm\.js/i, name: 'Google Tag Manager' },
  { re: /recaptcha\/api\.js|google\.com\/recaptcha|recaptcha\.net/i, name: 'Google reCAPTCHA' },
  { re: /\/turnstile\//i, name: 'Cloudflare Turnstile' },
  { re: /\/(cdnjs|cdnjs)\.googleapis\.com|ajax\.googleapis\.com/i, name: 'Google CDN' },
  { re: /cdn\.jsdelivr\.net/i, name: 'jsDelivr CDN' },
  { re: /unpkg\.com/i, name: 'unpkg CDN' },
  { re: /cdnjs\.cloudflare\.com/i, name: 'Cloudflare CDN (cdnjs)' },
  { re: /\/cdn-cgi\//i, name: 'Cloudflare (CDN/边缘)' },
  { re: /\/_next\/image|images\.cloudinary\.com|cloudfront\.net|imgix\.net/i, name: '图片 CDN/处理服务' }
]

export const HTML_PATTERNS: PatternRule[] = [
  { re: /<div[^>]+id="__next"/i, name: 'Next.js' },
  { re: /data-react(root|id)=/i, name: 'React' },
  { re: /ng-version=/i, name: 'Angular', version: 'ng-version' },
  { re: /ng-app[ >=]/i, name: 'AngularJS' },
  { re: /v-cloak|data-v-[0-9a-f]{8}/i, name: 'Vue' },
  { re: /window\.__NEXT_DATA__/i, name: 'Next.js' },
  { re: /window\.__NUXT__|data-n-head/i, name: 'Nuxt.js' },
  { re: /window\.__INITIAL_STATE__/i, name: 'SSR 状态注水 (常见 Vue/Nuxt)' },
  { re: /class="[^"]*\belementor-/i, name: 'Elementor (WordPress)' },
  { re: /wp-json|wp-content|wp-includes/i, name: 'WordPress' },
  { re: /data-turbo|turbolinks/i, name: 'Hotwire / Turbolinks (Rails)' },
  { re: /<amp-|data-amp/i, name: 'AMP' },
  { re: /csrf-token|name="_token"/i, name: 'CSRF token 存在 (Rails/Laravel 等)' }
]

export const GLOBAL_VARS: GlobalVarProbe[] = [
  { probe: 'jQuery', name: 'jQuery', versionPaths: ['jQuery.fn.jquery'] },
  { probe: '$', name: 'jQuery / $ (弱)', weak: true },
  { probe: 'Zepto', name: 'Zepto', versionPaths: ['Zepto.fn.zpto'] },
  { probe: 'Vue', name: 'Vue', versionPaths: ['Vue.version'] },
  { probe: '__VUE__', name: 'Vue 3' },
  { probe: 'React', name: 'React' },
  { probe: 'ReactDOM', name: 'React DOM' },
  { probe: 'ng', name: 'AngularJS', versionPaths: ['ng.versionInfo.full'] },
  { probe: 'Zone', name: 'Angular (Zone.js)' },
  { probe: '__NEXT_DATA__', name: 'Next.js' },
  { probe: '__NUXT__', name: 'Nuxt.js' },
  { probe: '__svelte__', name: 'Svelte' },
  { probe: 'dojo', name: 'Dojo' },
  { probe: 'dijit', name: 'Dojo (Dijit)' },
  { probe: 'Prototype', name: 'Prototype.js' },
  { probe: 'Ember', name: 'Ember', versionPaths: ['Ember.VERSION'] },
  { probe: 'Backbone', name: 'Backbone.js' },
  { probe: 'Handlebars', name: 'Handlebars' },
  { probe: 'THREE', name: 'Three.js' },
  { probe: 'd3', name: 'D3', versionPaths: ['d3.version'] },
  { probe: 'Chart', name: 'Chart.js', versionPaths: ['Chart.version'] },
  { probe: 'Highcharts', name: 'Highcharts', versionPaths: ['Highcharts.product', 'Highcharts.version'] },
  { probe: 'echarts', name: 'Apache ECharts', versionPaths: ['echarts.version'] },
  { probe: 'moment', name: 'Moment.js' },
  { probe: 'dayjs', name: 'Day.js' },
  { probe: '_', name: 'lodash', versionPaths: ['_.VERSION'] },
  { probe: 'axios', name: 'Axios', versionPaths: ['axios.defaults.version'] },
  { probe: 'Modernizr', name: 'Modernizr' },
  { probe: 'tinymce', name: 'TinyMCE', versionPaths: ['tinymce.majorVersion'] },
  { probe: 'CKEDITOR', name: 'CKEditor', versionPaths: ['CKEDITOR.version'] },
  { probe: 'io', name: 'Socket.IO (weak)', weak: true },
  { probe: 'SockJS', name: 'SockJS' },
  { probe: 'firebase', name: 'Firebase' },
  { probe: 'Sentry', name: 'Sentry' },
  { probe: 'dataLayer', name: 'Google Tag Manager / G4A' },
  { probe: 'gtag', name: 'Google Analytics (gtag)' },
  { probe: 'ga', name: 'Google Analytics', weak: true },
  { probe: 'fbq', name: 'Meta/Facebook Pixel' },
  { probe: 'utag', name: 'Tealium IQ' },
  { probe: '_satellite', name: 'Adobe Launch/Analytics' },
  { probe: 'hotjar', name: 'Hotjar' },
  { probe: 'hjSiteSettings', name: 'Hotjar' },
  { probe: 'intercom', name: 'Intercom' },
  { probe: '_hsq', name: 'HubSpot' },
  { probe: 'recaptcha', name: 'Google reCAPTCHA' },
  { probe: 'turnstile', name: 'Cloudflare Turnstile' },
  { probe: 'Yandex', name: 'Yandex Metrika' },
  { probe: '_baq', name: 'Baidu Analytics (百度统计)' },
  { probe: 'cnzz', name: 'CNZZ/友盟' },
  { probe: 'ko', name: 'Knockout.js', weak: true },
  { probe: 'Swiper', name: 'Swiper' },
  { probe: 'gsap', name: 'GSAP' },
  { probe: 'analytics', name: 'Segment / analytics.js', weak: true },
  { probe: 'mixpanel', name: 'Mixpanel' },
  { probe: 'amplitude', name: 'Amplitude' },
  { probe: 'Klaviyo', name: 'Klaviyo' },
  { probe: 'optimizely', name: 'Optimizely' },
  { probe: '__featureFlags', name: 'LaunchDarkly' },
  { probe: 'webpackChunk', name: 'Webpack 打包' },
  { probe: 'webpackChunk_N_E', name: 'Next.js (webpack)' },
  { probe: 'regeneratorRuntime', name: 'Babel/regenerator' }
]

export const WAF_RULES: WafRule[] = [
  {
    name: 'Cloudflare',
    vendor: 'Cloudflare',
    headers: [{ n: 'cf-ray' }, { n: 'cf-cache-status' }, { n: 'server', v: /cloudflare/i }, { n: 'x-served-by' }],
    cookies: [/^cf_clearance$/, /^__cf_bm$/, /^__cfduid$/],
    html: [/cdn-cgi\/l\/email-protection/i, /challenge-platform/i, /cf-chl/i],
    note: '常见 CDN+边缘防护，命中不代表站点源站有防护。'
  },
  {
    name: 'Akamai (Ghost)',
    vendor: 'Akamai',
    headers: [{ n: 'server', v: /AkamaiGHost/i }, { n: 'x-akamai-transformed' }, { n: 'mpulse' }],
    cookies: [/^AKAMAID?/, /^bm_sz$/, /^_abck$/, /^s_ppv$/],
    html: [/\/akam\.?/, /bob\/\d+\.\d+\.\d+\/akamai\.js/i]
  },
  {
    name: 'AWS WAF / CloudFront',
    vendor: 'Amazon',
    headers: [{ n: 'x-amz-cf-id' }, { n: 'x-amzn-waf-evaluate', v: /BLOCK|ALLOW/i }, { n: 'via', v: /cloudfront/i }],
    cookies: [/^AWSALB/, /^AWSALBCORS/, /^awswaf/]
  },
  {
    name: '阿里云 WAF',
    vendor: 'Alibaba Cloud',
    headers: [{ n: 'server', v: /Tengine|Aliyun/i }],
    cookies: [/^acw_tc$/, /^acw_sc/, /^aliyungf_tc$/, /^cdn_sec_tc$/],
    html: [/waf\/1\.0\.0\/js\/content\.js/i, /AliyunSef/i]
  },
  {
    name: '腾讯云 WAF',
    vendor: 'Tencent Cloud',
    headers: [{ n: 'x-tencent-waf' }],
    cookies: [/^TencentWafSessionId/, /wafclientid/i]
  },
  {
    name: 'F5 BIG-IP (ASM)',
    vendor: 'F5',
    headers: [{ n: 'server', v: /Big-?IP/i }, { n: 'x-iap-i24' }],
    cookies: [/^BIGipServer/, /^LastMRH_Session/, /^MRHSession$/]
  },
  {
    name: 'Imperva / Incapsula',
    vendor: 'Imperva',
    headers: [{ n: 'x-iinfo' }],
    cookies: [/^incap_ses_/, /^visid_incap_/, /^nlbi_/],
    html: [/_Incapsula_Resource/i]
  },
  {
    name: 'Radware (AppWall)',
    vendor: 'Radware',
    headers: [{ n: 'server', v: /DefensePro/i }],
    html: [/\bdist=\d+;ra=/i]
  },
  {
    name: 'Sucuri',
    vendor: 'Sucuri (GoDaddy)',
    headers: [{ n: 'server', v: /Sucuri\/Cloudproxy/i }, { n: 'x-sucuri-id' }],
    html: [/sucuri\/cloudproxy/i]
  },
  {
    name: '瑞数信息 (Riverse/BOTgate)',
    vendor: 'Riverse',
    headers: [{ n: 'server', v: /Riverge/i }],
    cookies: [/^S[\w-]+$/, /W[PN]/],
    html: [/\bwindow\._\$\$/i, /\/[\w]{6,20}\.[\w]{8,20}\.js/i, /\b_rs\b/],
    note: '动态混淆 JS + 一次性 Cookie 名是其典型特征。'
  },
  {
    name: '宝塔 WAF (Nginx)',
    vendor: 'BaoTa',
    headers: [{ n: 'server', v: /nginx|BWS/i }],
    html: [/\/www\.bt.cn|btpanel/i],
    note: '面板默认页面/错误页常见；生产环境少直接暴露。'
  },
  {
    name: 'Fastly',
    vendor: 'Fastly',
    headers: [{ n: 'x-served-by', v: /cache-/i }, { n: 'x-timer' }]
  },
  {
    name: 'Varnish',
    vendor: 'Varnish',
    headers: [{ n: 'via', v: /varnish/i }, { n: 'x-varnish' }]
  },
  {
    name: 'CDN: 网宿/蓝讯 (wswebcdn / wsrid)',
    vendor: 'ChinaNetcenter/Wangsu',
    headers: [{ n: 'wsbl', v: /\d/ }, { n: 'x-ws' }],
    cookies: [/^wsrid$/]
  }
]

export function identifyFromUrl(url: string): { name: string; version: string | null } | null {
  for (const p of URL_LIB_PATTERNS) {
    const m = url.match(p.re)
    if (m) return { name: p.name, version: versionFrom(m[1] || url) }
  }
  return null
}
