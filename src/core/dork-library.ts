// Dork 语法库（自 lib/dork-library.js 迁移为 ES 模块；通用 recon 包 + 教育预设包，仅生成查询）
export const ENGINE_BASE: Record<string, string> = {
  google: 'https://www.google.com/search?q=',
  bing: 'https://www.bing.com/search?q=',
  baidu: 'https://www.baidu.com/s?wd='
}

export interface CategoryMeta {
  id: string
  name: string
  order: number
}
export const CATEGORY_META: CategoryMeta[] = [
  { id: 'panel', name: '后台入口', order: 0 },
  { id: 'component', name: '组件指纹', order: 1 },
  { id: 'config', name: '配置泄露', order: 2 },
  { id: 'directory', name: '目录遍历', order: 3 },
  { id: 'auth', name: '认证/VPN', order: 4 },
  { id: 'error', name: '报错/调试', order: 5 },
  { id: 'api', name: 'API/接口文档', order: 6 },
  { id: 'general', name: '通用侦察', order: 7 },
  { id: 'leak_docs', name: '敏感文档(教育)', order: 8 },
  { id: 'pii', name: '个人信息(教育)', order: 9 },
  { id: 'sso', name: '统一认证(教育)', order: 10 }
]

const EN = ['google', 'bing']
const ALL = ['google', 'bing', 'baidu']

export interface DorkEntry {
  id: string
  name: string
  template: string
  risk: string
  category: string
  builtin: boolean
  engines: { google: boolean; bing: boolean; baidu: boolean }
}

// 通用 recon 包（行业中立）：[category, id, name, template, risk, engines]
type Row = [string, string, string, string, string, string[]]
const GENERAL: Row[] = [
  ['panel', 'g_admin', '管理后台入口', 'site:{target_domain} (inurl:admin OR inurl:manage OR inurl:console OR inurl:backend OR intitle:"管理后台")', 'medium', ALL],
  ['panel', 'g_login', '登录面板', 'site:{target_domain} (inurl:login OR inurl:signin OR intitle:登录 OR intitle:login)', 'low', ALL],
  ['component', 'g_nacos', 'Nacos', 'site:{target_domain} (intitle:nacos OR inurl:nacos)', 'high', EN],
  ['component', 'g_druid', 'Druid 监控', 'site:{target_domain} (inurl:druid OR intitle:druid)', 'high', EN],
  ['component', 'g_swagger', 'Swagger', 'site:{target_domain} (inurl:swagger OR inurl:api-docs OR intitle:swagger)', 'high', EN],
  ['component', 'g_actuator', 'Spring Actuator', 'site:{target_domain} (inurl:actuator/env OR inurl:actuator/heapdump OR inurl:actuator/health)', 'high', EN],
  ['component', 'g_jenkins', 'Jenkins', 'site:{target_domain} (intitle:jenkins OR inurl:jenkins)', 'high', EN],
  ['component', 'g_pma', 'phpMyAdmin', 'site:{target_domain} (inurl:phpmyadmin OR intitle:phpMyAdmin)', 'high', EN],
  ['component', 'g_grafana', 'Grafana', 'site:{target_domain} (intitle:grafana OR inurl:grafana)', 'medium', EN],
  ['component', 'g_kibana', 'Kibana', 'site:{target_domain} (intitle:kibana OR inurl:kibana)', 'medium', EN],
  ['component', 'g_jupyter', 'Jupyter', 'site:{target_domain} (intitle:"jupyter" OR inurl:tree OR inurl:notebook)', 'high', EN],
  ['component', 'g_wpadmin', 'WordPress 后台', 'site:{target_domain} (inurl:wp-admin OR inurl:wp-login.php OR inurl:wp-content)', 'medium', ALL],
  ['config', 'g_git', '版本控制泄露', 'site:{target_domain} (inurl:.git OR inurl:.svn OR "Index of /.git")', 'high', EN],
  ['config', 'g_env', '环境/配置', 'site:{target_domain} (inurl:.env OR inurl:config.php OR inurl:web.config OR inurl:application.yml)', 'high', EN],
  ['config', 'g_backup', '备份/数据库', 'site:{target_domain} (filetype:sql OR filetype:db OR inurl:bak OR inurl:www.zip OR inurl:web.zip)', 'high', EN],
  ['config', 'g_connstr', '数据库连接串', 'site:{target_domain} ("jdbc:mysql" OR "connectionString" OR "password=" OR "redis://")', 'high', EN],
  ['directory', 'g_indexof', '开放目录', 'site:{target_domain} intitle:"index of" OR "parent directory"', 'medium', EN],
  ['directory', 'g_upload', '上传目录', 'site:{target_domain} (inurl:upload OR inurl:uploads OR inurl:file) "index of"', 'medium', EN],
  ['auth', 'g_vpn', 'VPN/WebVPN', 'site:{target_domain} (webvpn OR inurl:vpn OR intitle:VPN)', 'high', ALL],
  ['auth', 'g_sso', '单点登录', 'site:{target_domain} (inurl:sso OR inurl:cas OR intitle:统一认证 OR intitle:单点登录)', 'medium', ALL],
  ['error', 'g_error', '报错泄露', 'site:{target_domain} ("fatal error" OR "syntax error" OR "mysql error" OR "stack trace" OR "warning: php")', 'high', EN],
  ['error', 'g_debug', '调试开关', 'site:{target_domain} ("debug=true" OR inurl:phpinfo OR "xdebug")', 'medium', EN],
  ['api', 'g_api', 'API/接口清单', 'site:{target_domain} (inurl:graphql OR inurl:api-docs OR intitle:"接口文档" OR "openapi")', 'medium', EN],
  ['general', 'g_test', '测试/旧系统', 'site:{target_domain} (inurl:test OR inurl:dev OR inurl:staging OR inurl:old)', 'medium', ALL],
  ['general', 'g_sub', '子域/旁站线索', 'site:{target_domain} -www (inurl:http OR intitle:"error" OR "404")', 'low', EN]
]

// 教育行业预设包（来自 CrazyEdusrc）
const EDU: Row[] = [
  ['leak_docs', 'student_roster', '学生名单/花名册', 'site:{target_domain} (filetype:xls OR filetype:xlsx OR filetype:csv) (学生名单 OR 花名册 OR 学籍 OR 名单)', 'high', ALL],
  ['leak_docs', 'id_card_docs', '身份证号文档', 'site:{target_domain} (filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:pdf) (身份证 OR 身份证号 OR 证件号)', 'high', ALL],
  ['leak_docs', 'full_pii_table', '全字段表格', 'site:{target_domain} filetype:xlsx (姓名 AND 身份证 AND 学号)', 'high', ALL],
  ['leak_docs', 'salary_sheet', '工资/津贴/绩效表', 'site:{target_domain} (filetype:xls OR filetype:xlsx) (工资 OR 津贴 OR 绩效 OR 补贴) (名单 OR 表)', 'high', ALL],
  ['leak_docs', 'admission', '录取/招生名单', 'site:{target_domain} (filetype:xls OR filetype:xlsx OR filetype:pdf) (录取 OR 拟录取 OR 新生 OR 招生名单)', 'high', ALL],
  ['leak_docs', 'score_docs', '成绩单文档', 'site:{target_domain} (filetype:xls OR filetype:xlsx OR filetype:pdf) (成绩 OR 分数线 OR 绩点)', 'medium', ALL],
  ['leak_docs', 'scholarship', '奖助学金公示', 'site:{target_domain} (奖学金 OR 助学金 OR 贫困生) (名单 OR 公示 OR filetype:xls)', 'medium', ALL],
  ['leak_docs', 'teacher_info', '教职工信息', 'site:{target_domain} (filetype:xls OR filetype:doc) (职工 OR 教师) (电话 OR 联系方式)', 'medium', ALL],
  ['pii', 'pii_keyword', '身份证+手机号关键词', 'site:{target_domain} ("身份证" AND "手机" AND "姓名") -招聘 -模板', 'high', ALL],
  ['pii', 'counsel_record', '心理咨询/谈话记录', 'site:{target_domain} (心理咨询 OR 谈话记录 OR 重点关注学生)', 'medium', ALL],
  ['pii', 'resume_leak', '简历泄露', 'site:{target_domain} (filetype:doc OR filetype:pdf) (简历 OR 个人简历)', 'medium', ALL],
  ['pii', 'pwd_in_doc', '文档内口令/账号', 'site:{target_domain} (filetype:xls OR filetype:doc OR filetype:pdf) ("初始密码" OR "默认密码")', 'high', ALL],
  ['panel', 'admin_login', '管理后台入口', 'site:{target_domain} (inurl:admin OR inurl:manage OR inurl:guanli OR intitle:后台)', 'medium', ALL],
  ['panel', 'oa_system', 'OA 办公系统', 'site:{target_domain} (inurl:oa OR intitle:OA OR 办公系统)', 'medium', ALL],
  ['panel', 'jwc_panel', '教务处后台', 'site:{target_domain} (inurl:jwc OR inurl:jwcweb OR intitle:教务处)', 'medium', ALL],
  ['panel', 'pay_system', '缴费/财务系统', 'site:{target_domain} (缴费 OR inurl:pay OR inurl:caiwu)', 'medium', ALL],
  ['sso', 'cas_login', 'CAS 统一认证', 'site:{target_domain} (inurl:cas OR intitle:统一身份认证)', 'high', ALL],
  ['sso', 'ehall_portal', '办事大厅', 'site:{target_domain} (inurl:ehall OR inurl:portal OR intitle:办事大厅)', 'high', ALL],
  ['sso', 'webvpn', 'WebVPN 入口', 'site:{target_domain} (webvpn OR inurl:vpn OR intitle:VPN)', 'high', ALL],
  ['sso', 'sangfor_vpn', '深信服 VPN 指纹', 'site:{target_domain} (inurl:por/login_psw.csp OR "EasyConnect")', 'high', EN],
  ['component', 'zf_jw_new', '正方教务(新版)', 'site:{target_domain} (inurl:jwglxt OR intitle:正方)', 'high', ALL],
  ['component', 'qz_jw', '强智教务', 'site:{target_domain} (inurl:jsxsd OR inurl:qzgd OR 强智)', 'high', ALL],
  ['component', 'kg_jw', '青果教务', 'site:{target_domain} (青果 OR inurl:kingsun)', 'high', ALL],
  ['component', 'weaver_oa', '泛微 OA', 'site:{target_domain} (inurl:/weaver/ OR inurl:/ecology/ OR intitle:泛微)', 'high', EN],
  ['component', 'seeyon_oa', '致远 OA', 'site:{target_domain} (inurl:/seeyon/ OR intitle:致远)', 'high', EN],
  ['component', 'tongda_oa', '通达 OA', 'site:{target_domain} (inurl:/general/ OR inurl:/ispirit/ OR intitle:通达OA)', 'high', EN],
  ['component', 'yonyou_nc', '用友 NC/U8', 'site:{target_domain} (inurl:/nc/ OR inurl:u8c OR intitle:用友)', 'high', EN],
  ['config', 'sql_dump', '数据库备份', 'site:{target_domain} (filetype:sql OR filetype:db OR filetype:mdb OR inurl:dump)', 'high', EN],
  ['config', 'env_config', '环境配置文件', 'site:{target_domain} (inurl:.env OR inurl:config.php OR inurl:web.config)', 'high', EN],
  ['config', 'git_svn', '版本控制泄露', 'site:{target_domain} (inurl:.git OR inurl:.svn OR "Index of /.git")', 'high', EN],
  ['directory', 'open_dir', '开放目录列表', 'site:{target_domain} intitle:"index of" OR "parent directory"', 'medium', EN],
  ['error', 'error_info', '报错信息泄露', 'site:{target_domain} ("fatal error" OR "syntax error" OR "mysql error" OR "sql语法错误")', 'high', EN],
  ['general', 'weak_admin', '弱口令/默认口令', 'site:{target_domain} ("默认密码" OR "初始密码" OR "admin123")', 'medium', ALL],
  ['general', 'upload_endpoint', '上传接口暴露', 'site:{target_domain} (inurl:upload OR inurl:fileupload OR inurl:uploadify)', 'medium', EN]
]

function seed(rows: Row[]): DorkEntry[] {
  return rows.map((r) => {
    const engines = r[5] || ALL
    return {
      id: r[1],
      name: r[2],
      template: r[3],
      risk: r[4],
      category: r[0],
      builtin: true,
      engines: { google: engines.indexOf('google') >= 0, bing: engines.indexOf('bing') >= 0, baidu: engines.indexOf('baidu') >= 0 }
    }
  })
}

export const PACKAGES: Record<string, DorkEntry[]> = { general: seed(GENERAL), edu: seed(EDU) }

export const GLOBAL_QUERIES: Array<{ id: string; name: string; template: string }> = [
  { id: 'g_docs', name: '敏感文档(xls/xlsx)', template: 'site:edu.cn (filetype:xls OR filetype:xlsx) (学生名单 OR 花名册 OR 身份证)' },
  { id: 'g_admin', name: '后台登录入口', template: 'site:edu.cn (inurl:admin OR intitle:后台登录)' },
  { id: 'g_cas', name: 'CAS 统一认证', template: 'site:edu.cn (inurl:cas/login OR intitle:统一身份认证)' },
  { id: 'g_dir', name: '开放目录', template: 'site:edu.cn intitle:"index of"' },
  { id: 'g_config', name: '配置/备份文件', template: 'site:edu.cn (filetype:sql OR inurl:.env OR inurl:.git)' }
]

export function fillTemplate(template: string, domain: string): string {
  return String(template).replace(/\{target_domain\}/g, domain || '').replace(/\{domain\}/g, domain || '')
}

export function buildSearchUrl(template: string, domain: string, engine: string): string {
  const base = ENGINE_BASE[engine] || ENGINE_BASE.google
  return base + encodeURIComponent(fillTemplate(template, domain))
}

export interface SearchItem {
  id: string
  name: string
  category: string
  risk: string
  query: string
  url: string
  engine: string
}

export function toSearchItems(entries: DorkEntry[] | null | undefined, domain: string, engine: string): SearchItem[] {
  if (!domain) return []
  return (entries || []).map((e) => ({
    id: e.id,
    name: e.name,
    category: e.category,
    risk: e.risk,
    query: fillTemplate(e.template, domain),
    url: buildSearchUrl(e.template, domain, engine),
    engine: ENGINE_BASE[engine] ? engine : 'google'
  }))
}

export function highRisk(pkgName: string): DorkEntry[] {
  const list = PACKAGES[pkgName] || []
  return list.filter((e) => e.risk === 'high')
}

export function listPackage(pkgName: string): DorkEntry[] {
  return (PACKAGES[pkgName] || []).slice()
}

export function validateImport(data: any): { ok: boolean; error?: string; count?: number } {
  if (!Array.isArray(data)) return { ok: false, error: '顶层需为数组' }
  const bad = data.findIndex((d) => !d || typeof d.name !== 'string' || typeof d.template !== 'string')
  if (bad >= 0) return { ok: false, error: '第 ' + (bad + 1) + ' 条缺少 name 或 template' }
  return { ok: true, count: data.length }
}

export function mergeUser(pkgName: string, userEntries: any[]): DorkEntry[] {
  const base = PACKAGES[pkgName] || []
  const ids = new Set(base.map((b) => b.id))
  const extra: DorkEntry[] = (userEntries || []).map((u) => ({
    id: 'user_' + (u.id || u.name),
    name: u.name,
    template: u.template,
    risk: u.risk || 'medium',
    category: u.category || 'general',
    builtin: false,
    engines: u.engines || { google: true, bing: true, baidu: true }
  }))
  return base.concat(extra.filter((e) => !ids.has(e.id)))
}
