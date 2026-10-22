<template>
  <div class="res" v-if="bundle">
    <header class="bar">
      <h1>ReconX 采集结果</h1>
      <span class="u">{{ bundle.meta.url }}</span>
      <el-dropdown trigger="click" @command="onExport">
        <el-button size="small">导出<el-icon><ArrowDown /></el-icon></el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="json">JSON</el-dropdown-item>
            <el-dropdown-item command="csv">CSV</el-dropdown-item>
            <el-dropdown-item command="md">Markdown 报告</el-dropdown-item>
            <el-dropdown-item command="src">SRC 提交草稿</el-dropdown-item>
            <el-dropdown-item command="html">HTML 报告</el-dropdown-item>
            <el-dropdown-item command="txt">端点 TXT</el-dropdown-item>
            <el-dropdown-item command="full" divided>综合报告 MD（含接管/路由/审计）</el-dropdown-item>
            <el-dropdown-item command="all">全部格式批量导出</el-dropdown-item>
            <el-dropdown-item command="multi" divided>聚合导出 MD（选既往结果合并）</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
      <el-select v-model="exportMinSeverity" size="small" style="width:120px" placeholder="全等级" title="导出前按风险等级过滤（filterBundle）">
        <el-option label="全等级" value="" />
        <el-option label="中危及以上" value="medium" />
        <el-option label="高危及以上" value="high" />
        <el-option label="仅严重" value="critical" />
      </el-select>
      <input ref="fileInput" type="file" accept=".json" multiple hidden @change="onFilesPicked" />
      <el-button size="small" @click="copyRaw">复制原始 JSON</el-button>
    </header>
    <el-alert v-if="bundle.storageTruncated" type="warning" :closable="false" class="mb"
      :title="'结果超出存储配额，已保存截断副本（部分长表不全）· ' + new Date(bundle.storageTruncated.at).toLocaleString('zh-CN') + ' · ' + bundle.storageTruncated.reason" />

    <el-tabs v-model="tab" class="tabs">
      <el-tab-pane label="概览" name="overview">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="主机">{{ bundle.meta.host }}</el-descriptions-item>
          <el-descriptions-item label="采集时间">{{ new Date(bundle.meta.collectedAt).toLocaleString('zh-CN') }}</el-descriptions-item>
          <el-descriptions-item label="框架（主源）">{{ primary.frameworkText }} {{ primary.versionText !== '—' ? primary.versionText : '' }}</el-descriptions-item>
          <el-descriptions-item label="路由库（主源）">{{ primary.routerKind }}</el-descriptions-item>
          <el-descriptions-item label="端点总数">{{ (bundle.links && bundle.links.total) || 0 }}</el-descriptions-item>
          <el-descriptions-item label="同源端点">{{ (bundle.links && bundle.links.sameOriginCount) || 0 }}</el-descriptions-item>
          <el-descriptions-item label="链接过滤">
            搜索引擎跳转 {{ (bundle.links && bundle.links.engineSkipped) || 0 }} 条 ·
            黑名单 {{ (bundle.links && bundle.links.blacklistSkipped) || 0 }} 条（规则 {{ (bundle.links && bundle.links.blacklistRules) || 0 }} 条）
          </el-descriptions-item>
          <el-descriptions-item label="图标指纹" :title="bundle.meta.favicon ? bundle.meta.favicon.url : ''">
            {{ bundle.meta.favicon && bundle.meta.favicon.md5 ? bundle.meta.favicon.md5 : (bundle.meta.favicon && bundle.meta.favicon.error ? '未取到（' + bundle.meta.favicon.error + '）' : '无') }}
          </el-descriptions-item>
        </el-descriptions>
        <h3>风险摘要</h3>
        <el-table :data="bundle.risks || []" size="small">
          <el-table-column prop="level" label="等级" width="90" />
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="summary" label="摘要" />
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="技术栈" name="tech">
        <div class="tip">下表的置信度与证据在采集期计算，输入来自辅源 routerProbe 与响应头/资源指纹；框架与路由库的最终结论以「路由（双源）」分区的主源为准。</div>
        <el-table :data="techRows" size="small">
          <el-table-column prop="name" label="名称" width="200" />
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="version" label="版本" width="120" />
          <el-table-column prop="confidence" label="置信" width="80" />
          <el-table-column label="证据"><template #default="{ row }">{{ (row.evidence || []).join(' ; ') }}</template></el-table-column>
        </el-table>
        <h3>WAF / 边缘防护</h3>
        <el-table :data="bundle.waf || []" size="small">
          <el-table-column prop="name" label="名称" width="200" />
          <el-table-column prop="vendor" label="厂商" width="160" />
          <el-table-column label="证据"><template #default="{ row }">{{ (row.evidence || []).join(', ') }}</template></el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="路由（双源）" name="routes">
        <div class="tip">探测采用双路并列：主源为页面侧 <b>King-CrackX detector</b> 的全量分析结果，辅源为 background 同步注入的 <b>ReconX routerProbe</b>。主源识别不出技术栈时，辅源自动升为兜底主源；即使主源可用，辅源结果也一并列出，供交叉核对与人工判断。</div>

        <el-alert :type="compare.isFallback ? 'warning' : (compare.divergence.length ? 'warning' : 'success')" :closable="false" :title="compare.headline" class="mb" />

        <div class="dual">
          <div class="card">
            <div class="card-h"><el-tag size="small" :type="primary.role === 'fallback' ? 'warning' : 'primary'">{{ roleText[primary.role] }}</el-tag> {{ primary.label }}</div>
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="技术栈">{{ primary.frameworkText }}</el-descriptions-item>
              <el-descriptions-item label="版本">{{ primary.versionText }}</el-descriptions-item>
              <el-descriptions-item label="路由库">{{ primary.routerKind }}</el-descriptions-item>
              <el-descriptions-item label="基础路径">{{ primary.routerBase }}</el-descriptions-item>
              <el-descriptions-item label="页面推断路径">{{ primary.detectedBasePath }}</el-descriptions-item>
              <el-descriptions-item label="路由条数">{{ primary.routeCount }}</el-descriptions-item>
              <el-descriptions-item v-if="primary.note" label="说明">{{ primary.note }}</el-descriptions-item>
            </el-descriptions>
          </div>
          <div class="card">
            <div class="card-h"><el-tag size="small" :type="auxiliary.usable ? 'info' : 'danger'">{{ roleText[auxiliary.role] }}</el-tag> {{ auxiliary.label }}</div>
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="技术栈">{{ auxiliary.frameworkText }}</el-descriptions-item>
              <el-descriptions-item label="版本">{{ auxiliary.versionText }}</el-descriptions-item>
              <el-descriptions-item label="路由库">{{ auxiliary.routerKind }}</el-descriptions-item>
              <el-descriptions-item label="基础路径">{{ auxiliary.routerBase }}</el-descriptions-item>
              <el-descriptions-item label="页面推断路径">{{ auxiliary.detectedBasePath }}</el-descriptions-item>
              <el-descriptions-item label="路由条数">{{ auxiliary.routeCount }}</el-descriptions-item>
              <el-descriptions-item v-if="auxiliary.note" label="说明">{{ auxiliary.note }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </div>

        <template v-if="compare.divergence.length">
          <h3>两路分歧</h3>
          <ul class="div"><li v-for="(d, i) in compare.divergence" :key="i">{{ d }}</li></ul>
        </template>

        <h3>路由并表（共 {{ routeMatrix.length }} 条）</h3>
        <el-table v-if="routeMatrix.length" :data="paged('routeMatrix', routeMatrix)" size="small">
          <el-table-column prop="path" label="路径" />
          <el-table-column :label="'✔ ' + primary.label" width="150"><template #default="{ row }">{{ row.inPrimary ? '✔' : '' }}</template></el-table-column>
          <el-table-column :label="'✔ ' + auxiliary.label" width="150"><template #default="{ row }">{{ row.inAux ? '✔' : '' }}</template></el-table-column>
          <el-table-column label="仅一方" width="110"><template #default="{ row }">{{ row.inPrimary !== row.inAux ? '需核对' : '' }}</template></el-table-column>
        </el-table>
        <Pager v-if="routeMatrix.length" v-model:page="pg.routeMatrix.page" v-model:size="pg.routeMatrix.size" :total="routeMatrix.length" />
        <div v-else class="empty">两路均未给出可展示的路由条目。</div>
      </el-tab-pane>
      <el-tab-pane label="API" name="api">
        <h3>已调用接口（performance fetch/xhr，共 {{ ((bundle.api && bundle.api.liveApis) || []).length }} 条）</h3>
        <el-table :data="paged('apiLive', bundle.api && bundle.api.liveApis)" size="small">
          <el-table-column prop="path" label="路径" />
          <el-table-column label="URL"><template #default="{ row }"><code>{{ row.url }}</code></template></el-table-column>
        </el-table>
        <Pager v-model:page="pg.apiLive.page" v-model:size="pg.apiLive.size" :total="((bundle.api && bundle.api.liveApis) || []).length" />
        <h3>静态提取端点（含是否被调用，共 {{ ((bundle.api && bundle.api.staticApis) || []).length }} 条）</h3>
        <el-table :data="paged('apiStatic', bundle.api && bundle.api.staticApis)" size="small">
          <el-table-column prop="path" label="路径" />
          <el-table-column label="已调用" width="90"><template #default="{ row }">{{ row.called ? '是' : '否' }}</template></el-table-column>
          <el-table-column prop="hasParams" label="含参数" width="90" />
          <el-table-column label="来源"><template #default="{ row }">{{ (row.sources || []).join(', ') }}</template></el-table-column>
        </el-table>
        <Pager v-model:page="pg.apiStatic.page" v-model:size="pg.apiStatic.size" :total="((bundle.api && bundle.api.staticApis) || []).length" />
        <h3>推断的后端基址（axios baseURL / env / JS 内出现域名，共 {{ ((bundle.js && bundle.js.baseUrls) || []).length }} 条）</h3>
        <el-table v-if="bundle.js && bundle.js.baseUrls && bundle.js.baseUrls.length" :data="bundle.js.baseUrls" size="small">
          <el-table-column prop="value" label="基址" />
          <el-table-column prop="kind" label="类型" width="90" />
          <el-table-column label="跨域" width="70"><template #default="{ row }">{{ isCrossOrigin(row.value) ? '是' : '否' }}</template></el-table-column>
          <el-table-column label="来源"><template #default="{ row }">{{ (row.sources || []).join(', ') }}</template></el-table-column>
        </el-table>
        <div v-else class="empty">未从 JS 中推断出后端基址。</div>
      </el-tab-pane>

      <el-tab-pane label="安全" name="security">
        <template v-if="bundle.security">
          <el-alert :title="'整体风险：' + riskLabel(bundle.security.summary.overallRisk) + ' · 敏感API ' + bundle.security.summary.sensitiveApiCount + ' · 待核验路由 ' + bundle.security.summary.unprotectedRoutes + ' · 预期公开 ' + (bundle.security.summary.publicRoutes || 0) + ' 条未计入'" type="warning" :closable="false" />
          <h3>敏感接口线索（共 {{ (bundle.security.sensitiveApis || []).length }} 条，全部保留可翻页查看）</h3>
          <el-table :data="paged('sensitive', bundle.security.sensitiveApis)" size="small">
            <el-table-column prop="category" label="类别" width="120" />
            <el-table-column prop="riskLevel" label="风险" width="90" />
            <el-table-column prop="path" label="路径" />
            <el-table-column prop="source" label="来源" width="90" />
          </el-table>
          <Pager v-model:page="pg.sensitive.page" v-model:size="pg.sensitive.size" :total="(bundle.security.sensitiveApis || []).length" />
          <h3>建议</h3>
          <ul><li v-for="(r, i) in bundle.security.recommendations || []" :key="i">{{ r }}</li></ul>
        </template>
        <div v-else class="empty">未生成安全审计。</div>
      </el-tab-pane>

      <el-tab-pane label="主动探测" name="probes">
        <template v-if="bundle.probes && bundle.probes.performed">
          <el-table :data="bundle.probes.results || []" size="small">
            <el-table-column prop="path" label="路径" />
            <el-table-column prop="status" label="状态" width="80" />
            <el-table-column prop="bytes" label="字节" width="90" />
            <el-table-column label="命中" width="80"><template #default="{ row }">{{ row.matched ? '命中' : '' }}</template></el-table-column>
            <el-table-column prop="desc" label="说明" />
          </el-table>
          <template v-if="bundle.probes.routes && bundle.probes.routes.applicable">
            <h3>前端路由可达性（{{ bundle.probes.routes.framework }} · {{ bundle.probes.routes.routerKind }}）</h3>
            <div class="tip">共拼接 {{ (bundle.probes.routes.routeFullUrls || []).length }} 条完整路由 URL，探测其中前 {{ (bundle.probes.routes.routeProbes || []).length }} 条；全量列表会写入「综合报告 MD」的路由完整 URL 章节。</div>
            <el-table :data="bundle.probes.routes.routeProbes || []" size="small">
              <el-table-column prop="path" label="路由" />
              <el-table-column prop="status" label="状态" width="80" />
              <el-table-column prop="bytes" label="字节" width="90" />
              <el-table-column label="URL"><template #default="{ row }"><code>{{ row.url }}</code></template></el-table-column>
            </el-table>
          </template>
          <div v-else-if="bundle.probes.routes" class="tip">{{ bundle.probes.routes.reason }}</div>
        </template>
        <div v-else class="empty">未执行主动探测（需在范围内点击“主动探测”）。</div>
      </el-tab-pane>

      <el-tab-pane label="实时回传" name="live">
        <div class="tip">本页数据由页面脚本（detector / api-extractor / all-in）实时回传，与采集结果分键存储。回传站点：<b>{{ live.siteKey || '未知' }}</b> · 最近更新：{{ liveTime }}<span v-if="live.apiProgress"> · 进度：<b>{{ live.apiProgress }}</b></span></div>

        <h3>框架检测</h3>
        <el-descriptions v-if="live.frameworkDetection" :column="3" border size="small">
          <el-descriptions-item label="检出">{{ live.frameworkDetection.detected ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="框架">{{ live.frameworkDetection.framework || '-' }}</el-descriptions-item>
          <el-descriptions-item label="路由库">{{ live.frameworkDetection.routerKind || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Vue 版本">{{ live.frameworkDetection.vueVersion || '-' }}</el-descriptions-item>
          <el-descriptions-item label="React 版本">{{ live.frameworkDetection.reactVersion || '-' }}</el-descriptions-item>
          <el-descriptions-item label="路由已检出">{{ live.frameworkDetection.routerDetected ? '是' : '否' }}</el-descriptions-item>
        </el-descriptions>
        <div v-else class="empty">暂无框架检测回传。</div>

        <h3>拦截统计</h3>
        <el-descriptions v-if="liveAllIn" :column="3" border size="small">
          <el-descriptions-item label="已注入">{{ liveAllIn.injected ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="注入时间">{{ new Date(liveAllIn.injectedAt).toLocaleString('zh-CN') }}</el-descriptions-item>
          <el-descriptions-item label="最后事件">{{ liveAllIn.lastEvent || '-' }}</el-descriptions-item>
          <el-descriptions-item label="补丁路由数">{{ liveAllIn.routersPatched || 0 }}</el-descriptions-item>
          <el-descriptions-item label="守卫拦截数">{{ liveAllIn.guardRegistrationBlocked || 0 }}</el-descriptions-item>
          <el-descriptions-item label="Router 跳转拦截">{{ liveAllIn.routerJumpBlocked || 0 }}</el-descriptions-item>
          <el-descriptions-item label="浏览器跳转拦截">{{ liveAllIn.browserJumpBlocked || 0 }}</el-descriptions-item>
        </el-descriptions>
        <div v-else class="empty">暂无拦截统计回传。</div>

        <div class="tip">detector 的路由分析结果已并入「路由（双源）」分区，与辅源并排呈现，此处不再重复。</div>

        <h3>API 提取</h3>
        <template v-if="liveApi">
          <div class="tip">已调用 {{ liveApiStats.liveCount }} · 静态 {{ liveApiStats.staticCount }}（未调用 {{ liveApiStats.uncalledCount }}） · Sourcemap {{ liveApiStats.sourceMapCount }} · JS {{ liveApiStats.scriptCount }} 个 / 内联 {{ liveApiStats.inlineCount }} 段 / 失败 {{ liveApiStats.failedCount }} 个</div>
          <el-table :data="paged('liveApiStatic', liveApi.staticApis)" size="small">
            <el-table-column prop="path" label="路径" />
            <el-table-column label="完整 URL"><template #default="{ row }"><code>{{ row.fullUrl || row.url || row.path }}</code></template></el-table-column>
            <el-table-column label="已调用" width="90"><template #default="{ row }">{{ row.called ? '是' : '否' }}</template></el-table-column>
            <el-table-column label="来源" width="180"><template #default="{ row }">{{ (row.sources || []).join(', ') }}</template></el-table-column>
          </el-table>
          <Pager v-model:page="pg.liveApiStatic.page" v-model:size="pg.liveApiStatic.size" :total="(liveApi.staticApis || []).length" />
        </template>
        <div v-else class="empty">暂无 API 提取回传。</div>

        <template v-if="liveErrors.length">
          <h3>回传错误</h3>
          <ul><li v-for="[k, v] in liveErrors" :key="k"><code>{{ k }}</code> — {{ v }}</li></ul>
        </template>
      </el-tab-pane>

      <el-tab-pane label="Dork 与资产测绘" name="dork">
        <div class="bar" style="margin-bottom:8px">
          <el-input v-model="assetDomain" size="small" placeholder="目标主域" style="width:220px" clearable />
          <span class="tip">只生成查询语法与检索地址，扩展不会自动打开标签页或发生跳转；请在已授权范围内自行核对。域名对下面三个分区同时生效。</span>
        </div>

        <el-tabs v-model="dorkTab" class="subtabs">
          <el-tab-pane label="Dork 语法" name="queries">
            <div class="bar" style="margin-bottom:8px">
              <el-select v-model="dorkPkg" size="small" style="width:150px">
                <el-option label="通用侦察包" value="general" />
                <el-option label="教育行业包" value="edu" />
              </el-select>
              <el-select v-model="dorkEngine" size="small" style="width:120px">
                <el-option label="Google" value="google" />
                <el-option label="Bing" value="bing" />
                <el-option label="Baidu" value="baidu" />
              </el-select>
              <el-checkbox v-model="dorkHighOnly" size="small">仅高风险</el-checkbox>
              <span class="tip">共 {{ dorkItems.length }} 条{{ userDorks[dorkPkg].length ? '（含自定义 ' + userDorks[dorkPkg].length + ' 条）' : '' }}</span>
            </div>
            <el-table :data="dorkItems" size="small">
              <el-table-column label="类别" width="150"><template #default="{ row }">{{ dorkCategoryName(row.category) }}</template></el-table-column>
              <el-table-column prop="name" label="名称" width="160" />
              <el-table-column label="风险" width="80"><template #default="{ row }">{{ riskLabel(row.risk) }}</template></el-table-column>
              <el-table-column label="查询语法"><template #default="{ row }"><code>{{ row.query }}</code></template></el-table-column>
              <el-table-column label="" width="100"><template #default="{ row }"><el-button size="small" text @click="copyText(row.query)">复制语法</el-button></template></el-table-column>
            </el-table>
            <h3>自定义 Dork 导入</h3>
            <div class="tip">粘贴 JSON 数组（形如 [{'name':'后台探测','template':'site:{target_domain} inurl:admin','risk':'high'}]），校验通过后并入当前包并持久保存。</div>
            <el-input v-model="dorkImportText" type="textarea" :rows="3" placeholder='[{"name":"...","template":"...","risk":"high"}]' style="margin-bottom:6px" />
            <div class="bar">
              <el-button size="small" @click="importDorks">校验并入当前包</el-button>
              <el-button v-if="userDorks[dorkPkg].length" size="small" @click="exportUserDorks">导出本包自定义备份</el-button>
              <el-button v-if="userDorks[dorkPkg].length" size="small" text type="danger" @click="clearUserDorks">清除本包自定义 {{ userDorks[dorkPkg].length }} 条</el-button>
              <span v-if="dorkImportMsg" class="tip">{{ dorkImportMsg }}</span>
            </div>

            <h3>行业全局查询（{{ GLOBAL_QUERIES.length }} 条，不限定当前域）</h3>
            <div class="tip">这些语法面向整个 edu.cn 域段，不随当前目标域名替换，适合行业面排查而非单点定位。</div>
            <el-table :data="GLOBAL_QUERIES" size="small">
              <el-table-column prop="name" label="名称" width="180" />
              <el-table-column label="查询语法"><template #default="{ row }"><code>{{ row.template }}</code></template></el-table-column>
              <el-table-column label="" width="100"><template #default="{ row }"><el-button size="small" text @click="copyText(row.template)">复制语法</el-button></template></el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="资产测绘（4 平台 × 4 模式）" name="asset">
            <div class="bar" style="margin-bottom:8px">
              <el-input v-model="assetKeyword" size="small" placeholder="关键词：组件指纹档填组件名（如 Nacos / 泛微），备案主体档填单位名称" style="width:460px" clearable />
            </div>
            <el-table :data="assetMatrix" size="small">
              <el-table-column prop="mode" label="模式" width="100" />
              <el-table-column label="用途" width="220"><template #default="{ row }"><span class="muted">{{ row.modeHint }}</span></template></el-table-column>
              <el-table-column prop="platform" label="平台" width="110" />
              <el-table-column label="账号限制" width="170"><template #default="{ row }"><span class="muted">{{ row.tip }}</span></template></el-table-column>
              <el-table-column label="查询语法"><template #default="{ row }"><code v-if="row.query">{{ row.query }}</code><span v-else class="muted">{{ assetStatus[row.status] }}</span></template></el-table-column>
              <el-table-column label="" width="100"><template #default="{ row }"><el-button v-if="row.query" size="small" text @click="copyText(row.query)">复制语法</el-button></template></el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="侦察入口" name="extra">
            <div class="tip">这些入口本身是站点检索页，此处只给出构造好的地址文本供你复制，不做跳转。</div>
            <el-table :data="extraSourceRows" size="small">
              <el-table-column prop="name" label="入口" width="140" />
              <el-table-column prop="hint" label="用途" width="320"><template #default="{ row }"><span class="muted">{{ row.hint }}</span></template></el-table-column>
              <el-table-column label="检索地址"><template #default="{ row }"><code v-if="row.addr">{{ row.addr }}</code><span v-else class="muted">需填域名</span></template></el-table-column>
              <el-table-column label="" width="100"><template #default="{ row }"><el-button v-if="row.addr" size="small" text @click="copyText(row.addr)">复制地址</el-button></template></el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </el-tab-pane>

      <el-tab-pane label="原始 JSON" name="raw">
        <pre class="rawjson" @click="selectPre">{{ JSON.stringify(bundle, null, 2) }}</pre>
      </el-tab-pane>
    </el-tabs>
  </div>
  <div v-else class="empty">尚无采集结果，请在弹窗中采集后打开本页。</div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted, toRaw } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { exportBundle, exportFullReport, exportMulti, filterBundle, parseJson, exportJson } from '../core/exporter'
import { applyTheme, resolveTheme } from '../shared/theme'
import { buildProbeCompare } from '../core/probe-sources'
import Pager from './Pager.vue'
import { listPackage, highRisk, mergeUser, validateImport, toSearchItems, CATEGORY_META, GLOBAL_QUERIES } from '../core/dork-library'
import { riskLabel } from '../core/sensitive-rules'
import { buildAssetMatrix, buildExtraSources } from '../core/asset-search'
const bundle = ref<any>(null)
const live = ref<any>({ updatedAt: 0 })
const tab = ref('overview')

const techRows = computed(() => {
  const ts = bundle.value && bundle.value.techStack
  if (ts && ts.items && ts.items.length) return ts.items
  return (bundle.value && bundle.value.tech) || []
})

const liveTime = computed(() => (live.value.updatedAt ? new Date(live.value.updatedAt).toLocaleString('zh-CN') : '—'))
const liveAllIn = computed<any | null>(() => (live.value.allInStatus && live.value.allInStatus.injectedAt ? live.value.allInStatus : null))
const liveApi = computed<any | null>(() => live.value.apiExtractResult || null)
const liveApiStats = computed(() => {
  const a = liveApi.value
  const statics: any[] = (a && a.staticApis) || []
  return {
    liveCount: ((a && a.liveApis) || []).length,
    staticCount: statics.length,
    uncalledCount: statics.filter((x: any) => !x.called).length,
    sourceMapCount: ((a && a.sourceMaps) || []).length,
    scriptCount: (a && a.scriptCount) || 0,
    inlineCount: (a && a.inlineScriptCount) || 0,
    failedCount: ((a && a.failedScripts) || []).length
  }
})
const liveErrors = computed<Array<[string, string]>>(() => Object.entries((live.value.errors || {}) as Record<string, string>))
// 后端基址是否跨域：value 的 host 与当前采集主机不同即为跨域（潜在外部后端/第三方）
function isCrossOrigin(value: string): boolean {
  try { return new URL(value).hostname !== ((bundle.value && bundle.value.meta && bundle.value.meta.host) || '') } catch { return false }
}

// 长表分页：仅用于行数随站点规模增长的表，固定长度的表直接全量展示
const pg = reactive<Record<string, { page: number; size: number }>>({
  routeMatrix: { page: 1, size: 50 },
  apiLive: { page: 1, size: 50 },
  apiStatic: { page: 1, size: 50 },
  sensitive: { page: 1, size: 50 },
  liveApiStatic: { page: 1, size: 50 }
})
function paged(key: string, list: any[] | null | undefined): any[] {
  const s = pg[key]
  const from = (s.page - 1) * s.size
  return (list || []).slice(from, from + s.size)
}

// 双源对比：主源 King detector（live.routerAnalysis），辅源 routerProbe（bundle.routes）
const compare = computed(() => buildProbeCompare(live.value.routerAnalysis, bundle.value && bundle.value.routes))
const primary = computed(() => compare.value.primary)
const auxiliary = computed(() => compare.value.auxiliary)
const roleText: Record<string, string> = { primary: '主源', auxiliary: '辅源', fallback: '兜底主源', unavailable: '无可用结果' }

/** 按路径合并两路路由，标出各自命中，便于人工判断分歧 */
const routeMatrix = computed(() => {
  const map = new Map<string, { path: string; inPrimary: boolean; inAux: boolean }>()
  const add = (list: any[], key: 'inPrimary' | 'inAux') => {
    (list || []).forEach((r: any) => {
      const p = String(r.path)
      const row = map.get(p) || { path: p, inPrimary: false, inAux: false }
      row[key] = true
      map.set(p, row)
    })
  }
  add(primary.value.routes, 'inPrimary')
  add(auxiliary.value.routes, 'inAux')
  return Array.from(map.values()).sort((a, b) => (Number(b.inPrimary) - Number(a.inPrimary)) || String(a.path).localeCompare(String(b.path)))
})

onMounted(async () => {
  const { lastBundle, settings, liveState, userDorks: ud } = await chrome.storage.local.get(['lastBundle', 'settings', 'liveState', 'userDorks'])
  applyTheme(resolveTheme(settings && settings.theme))
  bundle.value = lastBundle || null
  live.value = liveState || { updatedAt: 0 }
  assetDomain.value = (lastBundle && lastBundle.meta && lastBundle.meta.host) || ''
  if (ud && Array.isArray(ud.general)) userDorks.general = ud.general
  if (ud && Array.isArray(ud.edu)) userDorks.edu = ud.edu
})

async function copyRaw(): Promise<void> {
  const text = JSON.stringify(bundle.value, null, 2)
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
const dorkEngine = ref('google')
const dorkTab = ref('queries')
const dorkPkg = ref<'general' | 'edu'>('general')
const dorkHighOnly = ref(false)
const dorkImportText = ref('')
const dorkImportMsg = ref('')
/** 按包持久化的自定义 Dork（chrome.storage.local.userDorks，导入时经 validateImport 校验） */
const userDorks = reactive<Record<string, any[]>>({ general: [], edu: [] })

const DORK_CATEGORY = Object.fromEntries(CATEGORY_META.map((c) => [c.id, c.name])) as Record<string, string>
// 库内类别是英文 id，界面显示中文名；自定义条目的未知 id 原样返回
function dorkCategoryName(id: string): string { return DORK_CATEGORY[id] || id }
function exportUserDorks(): void { exportJson(toRaw(userDorks[dorkPkg.value]), 'reconx-dorks-' + dorkPkg.value) }

// 导出控制：等级过滤（filterBundle）+ 全量/多格式/聚合导出（exportFullReport/exportMulti）
const exportMinSeverity = ref('')
const fileInput = ref<HTMLInputElement | null>(null)

// bundle.value 是 Vue 响应式代理，filterBundle 内的 structuredClone 无法拷贝 Proxy，必须先 toRaw
function exportView(): any {
  const raw = toRaw(bundle.value)
  return exportMinSeverity.value ? filterBundle(raw, { minSeverity: exportMinSeverity.value }) : raw
}
function onExport(fmt: string): void {
  if (!bundle.value) return
  // 聚合导出要临时挑既往结果文件，交给隐藏 input，选完即导即忘，页面上不留常驻入口
  if (fmt === 'multi') { fileInput.value?.click(); return }
  const view = exportView()
  if (fmt === 'full') exportFullReport(view, (view.meta && view.meta.url) || '')
  else if (fmt === 'all') exportBundle(view, ['json', 'csv', 'md', 'src', 'html', 'txt'])
  else exportBundle(view, fmt)
}
async function onFilesPicked(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement
  const files = Array.from(input.files || [])
  const picked: any[] = []
  const bad: string[] = []
  for (const f of files) {
    // parseJson：安全解析，非法 JSON 只标记失败文件不中断
    const parsed = parseJson(await f.text())
    if (parsed.ok && parsed.data && parsed.data.meta) picked.push(parsed.data)
    else bad.push(f.name)
  }
  input.value = ''
  if (!picked.length) { ElMessage.error(bad.length ? '这些文件不是采集结果 JSON：' + bad.join('、') : '未选择有效文件'); return }
  exportMulti([exportView(), ...picked], 'md')
  ElMessage.success('已聚合导出 ' + (picked.length + 1) + ' 份结果' + (bad.length ? '，跳过 ' + bad.length + ' 个无效文件' : ''))
}
function importDorks(): void {
  const parsed = parseJson(dorkImportText.value)
  if (!parsed.ok) { dorkImportMsg.value = 'JSON 解析失败：' + parsed.error; return }
  const v = validateImport(parsed.data)
  if (!v.ok) { dorkImportMsg.value = '校验失败：' + v.error + '（顶层需为含 name/template 的数组）'; return }
  userDorks[dorkPkg.value] = parsed.data
  chrome.storage.local.set({ userDorks: { general: userDorks.general, edu: userDorks.edu } })
  dorkImportMsg.value = '已并入「' + (dorkPkg.value === 'edu' ? '教育行业包' : '通用侦察包') + '」' + v.count + ' 条并保存'
  dorkImportText.value = ''
}
function clearUserDorks(): void {
  userDorks[dorkPkg.value] = []
  chrome.storage.local.set({ userDorks: { general: userDorks.general, edu: userDorks.edu } })
  dorkImportMsg.value = '已清除本包自定义 Dork'
}
const dorkItems = computed(() => {
  const host = assetDomain.value.trim() || (bundle.value && bundle.value.meta && bundle.value.meta.host)
  if (!host) return []
  const custom = userDorks[dorkPkg.value]
  // 无自定义时高风险走 highRisk（内置包快路径），有自定义时 mergeUser 后统一过滤
  let entries = custom.length
    ? mergeUser(dorkPkg.value, custom)
    : dorkHighOnly.value
      ? highRisk(dorkPkg.value)
      : listPackage(dorkPkg.value)
  if (custom.length && dorkHighOnly.value) entries = entries.filter((e) => e.risk === 'high')
  return toSearchItems(entries, host, dorkEngine.value)
})
const assetDomain = ref('')
const assetKeyword = ref('')
const assetStatus: Record<string, string> = { unsupported: '该平台不支持', needKeyword: '需填关键词', needDomain: '需填域名' }

const assetMatrix = computed(() => buildAssetMatrix(assetDomain.value, assetKeyword.value))
const extraSourceRows = computed(() => buildExtraSources(assetDomain.value))
async function copyText(text: string): Promise<void> {
  // writeText 返回 Promise，必须 await 才能捕获失败；此前未 await，rejection 不进 catch，
  // execCommand 降级成了死代码，复制失败还毫无提示。
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      ta.remove()
      if (ok) ElMessage.success('已复制')
      else ElMessage.error('复制失败，请手动选择')
    } catch {
      ElMessage.error('复制失败，请手动选择')
    }
  }
}
function selectPre(e: MouseEvent): void {
  const el = e.target as HTMLElement
  const range = document.createRange()
  range.selectNodeContents(el)
  const sel = window.getSelection()
  sel?.removeAllRanges()
  sel?.addRange(range)
}
</script>

<style scoped>
.res { max-width: 1180px; margin: 0 auto; padding: 18px 22px 40px; font: 14px/1.6 var(--rx-font); color: var(--rx-text); }
.bar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.bar h1 { font-family: var(--rx-font-head); font-size: 18px; margin: 0; color: var(--rx-accent); text-shadow: var(--rx-glow); }
.u { flex: 1; color: var(--rx-muted); font-family: var(--rx-font); font-size: 12px; word-break: break-all; }
h3 { margin: 18px 0 8px; font-size: 14px; color: var(--rx-text); }
.tip { color: var(--rx-muted); font-size: 12px; margin-bottom: 8px; }
.muted { color: var(--rx-muted); font-size: 12px; }
.subtabs { padding-top: 2px; }
.subtabs :deep(.el-tabs__header) { margin-bottom: 10px; }
.empty { padding: 40px; text-align: center; color: var(--rx-muted); }
:deep(.el-table .is-current td.el-table__cell) { background: var(--rx-accent-soft); }
.rawjson { background: var(--rx-code-bg); color: var(--rx-text); padding: 14px; border-radius: 8px; box-shadow: var(--rx-glow); max-height: 560px; overflow: auto; font-family: var(--rx-font); font-size: 12px; white-space: pre-wrap; word-break: break-all; user-select: text; cursor: text; }
.mb { margin-bottom: 12px; }
.dual { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin: 12px 0; }
.card { border: 1px solid var(--rx-border); border-radius: 8px; padding: 10px 12px; background: var(--rx-bg-elev); }
.card-h { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: var(--rx-accent); }
.div { margin: 0 0 10px; padding-left: 20px; color: var(--rx-text); font-size: 13px; }
.div li { margin-bottom: 4px; }
</style>
