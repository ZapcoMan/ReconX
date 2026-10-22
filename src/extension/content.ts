/**
 * ReconX —— 内容脚本（ISOLATED world）
 *
 * 职责：作为扩展与页面之间的消息桥接层。
 *
 * 为什么需要它：
 *   all-in.js / api-extractor / tech-stack detector 必须运行在页面的 MAIN world
 *   才能访问 Vue/React 内部对象，但 MAIN world 无法直接使用 chrome.* API。
 *   因此由本脚本在 ISOLATED world 中完成两侧转发：
 *     页面脚本 --window.postMessage--> 本脚本 --chrome.runtime.sendMessage--> popup/background
 *     popup/background --chrome.runtime.sendMessage--> 本脚本 --注入 script--> 页面脚本
 */
(function () {
    /** 缓存的框架检测结果，供 popup 复用，避免重复分析 */
    let frameworkDetectionResult: {
        detected: boolean
        framework: 'vue' | 'react' | null
        vueVersion: string | null
        reactVersion: string | null
        routerDetected: boolean
        routerKind: string | null
        details: Record<string, unknown>
        errorMsg: string
    } = {
        detected: false,
        framework: null,
        vueVersion: null,
        reactVersion: null,
        routerDetected: false,
        routerKind: null,
        details: {},
        errorMsg: ''
    }

    /** 缓存的路由分析结果，供 popup 复用 */
    let routerAnalysisResult: Record<string, unknown> | null = null

    /** 防止同一页面重复注入 detector（注入未完成期间再次请求会直接返回） */
    let detectorInjectionInProgress = false

    /**
     * detector 注入看门狗定时器。
     *
     * 注入锁只能靠页面脚本回传的消息释放，但存在「消息永不到达」的卡死路径：
     *   - detectFramework 命中后走 analyzeAndReport，先 sendResult({detected:true})，
     *     该分支故意不释放锁（把释放押给 50ms 后的路由 RESULT/ERROR）；
     *   - 若 setTimeout 回调里的 performFullAnalysis 抛出、或 sendRouterResult 的兜底
     *     postMessage 再次抛错，则路由的 RESULT/ERROR 都发不出来，锁将永久为 true，
     *     此后每次重新检测/分析都被 injectDetector 静默拒绝，只能刷新页面才能恢复。
     *
     * 因此用超时兜底：注入时 armed，若在一个足够宽裕的窗口内没有任何终态消息，
     * 强制释放锁。窗口要远大于正常链路（延迟检测 0/300/600ms + 路由 50ms），
     * 只有真正卡死才会触发；收到 detected:true 时重新计时，给路由消息留出独立窗口。
     */
    const DETECTOR_LOCK_TIMEOUT_MS = 10000
    let detectorWatchdog: ReturnType<typeof setTimeout> | null = null

    /** 取消防狗（收到任一终态消息或注入失败时调用），避免后续误释放 */
    function clearDetectorWatchdog(): void {
        if (detectorWatchdog !== null) {
            clearTimeout(detectorWatchdog)
            detectorWatchdog = null
        }
    }

    /**
     * 释放注入锁并撤销看门狗。所有终态路径统一走这里，避免遗漏导致锁泄漏。
     * @param rearm - 传 true 表示当前并非终态（如刚收到 detected:true），
     *                需要保持锁占用并重新计时等待下一步消息
     */
    function releaseDetectorLock(rearm = false): void {
        clearDetectorWatchdog()
        if (rearm) {
            armDetectorWatchdog()
            return
        }
        detectorInjectionInProgress = false
    }

    /** 重新武装看门狗：超时后强制释放锁，兜住「消息永不到达」的卡死 */
    function armDetectorWatchdog(): void {
        clearDetectorWatchdog()
        detectorWatchdog = setTimeout(() => {
            detectorWatchdog = null
            detectorInjectionInProgress = false
        }, DETECTOR_LOCK_TIMEOUT_MS)
    }

    /**
     * 向页面注入技术栈检测脚本（MAIN world）以执行 Vue/React 检测与路由分析。
     *
     * 通过动态创建 <script> 并指向 web_accessible_resources 中的文件实现注入，
     * 脚本加载后立即移除 DOM 节点，避免污染页面结构。
     * 使用 detectorInjectionInProgress 做并发保护：分析未结束前重复调用会被忽略。
     * 同时武装看门狗定时器，兜住回传消息丢失导致的锁不释放。
     *
     * @returns true 表示已发起注入；false 表示被并发保护拦截或注入失败
     */
    function injectDetector(): boolean {
        if (detectorInjectionInProgress) {
            return false
        }

        try {
            detectorInjectionInProgress = true
            armDetectorWatchdog()
            const script = document.createElement('script')
            script.src = chrome.runtime.getURL('detector.js')
            // 加载成功后移除节点；注入是否成功由页面脚本回传的消息判定，
            // 故 onload 不释放锁——释放交给终态消息或看门狗超时。
            script.onload = function () {
                script.remove()
            }
            script.onerror = function () {
                releaseDetectorLock()
                script.remove()
                chrome.runtime.sendMessage({
                    action: "reconxDetectorError",
                    error: "detector.js 加载失败"
                })
            }
            ;(document.head || document.documentElement).appendChild(script)
            return true
        } catch (e) {
            releaseDetectorLock()
            console.error("Failed to inject detector script:", e)
            frameworkDetectionResult.errorMsg = String(e)
            chrome.runtime.sendMessage({
                action: "reconxDetectorError",
                error: String(e)
            })
            return false
        }
    }

    /**
     * 向页面注入 API 提取脚本（MAIN world）以提取 API 端点。
     *
     * 与 detector.js 不同，本脚本支持重复提取（每次点击「提取API」都应重新扫描），
     * 因此 URL 后拼接时间戳参数绕过浏览器缓存，确保每次都执行最新的脚本内容。
     *
     * @returns true 表示已发起注入；false 表示注入失败
     */
    function injectApiExtractor(): boolean {
        try {
            const script = document.createElement('script')
            // 附加时间戳参数，强制绕过缓存以支持重复提取
            script.src = chrome.runtime.getURL('api-extractor.js') + '?t=' + Date.now()
            script.onload = function () {
                script.remove()
            }
            script.onerror = function () {
                script.remove()
                chrome.runtime.sendMessage({
                    action: "reconxApiError",
                    error: "api-extractor.js 注入失败"
                })
            }
            ;(document.head || document.documentElement).appendChild(script)
            return true
        } catch (e) {
            console.error("Failed to inject api extractor:", e)
            chrome.runtime.sendMessage({
                action: "reconxApiError",
                error: String(e)
            })
            return false
        }
    }

    /**
     * 监听页面脚本通过 window.postMessage 回传的消息，并转发给 background/popup。
     *
     * 消息分三类：
     *   1. 框架检测 / 路由分析结果（来自 detector.js）—— 同时更新本地缓存
     *   2. 梭哈模式运行状态（来自 all-in.js）
     *   3. API 提取进度 / 结果 / 错误（来自 api-extractor.js）
     *
     * 安全校验：只处理 event.source === window 的消息，排除其他窗口/iframe 的干扰；
     * 对第三方来源的消息额外校验 event.data.source 字段，避免误转发。
     */
    window.addEventListener('message', function (event: MessageEvent) {
        // 只接受来自当前页面主世界的消息
        if (event.source !== window) return

        try {
            const data = event.data as Record<string, unknown>

            // ---- 类型 1：框架检测结果 ----
            if (data.type === 'RECONX_FRAMEWORK_DETECTION_RESULT') {
                frameworkDetectionResult = data.result as typeof frameworkDetectionResult
                if (!frameworkDetectionResult.detected) {
                    // 未检测到框架即为终态，释放锁
                    releaseDetectorLock()
                } else {
                    // 命中框架并非终态：detector.js 随后还会延迟回传路由结果。
                    // 保持锁占用并重新计时，给这条路由消息留出独立的看门狗窗口。
                    releaseDetectorLock(true)
                }

                chrome.runtime.sendMessage({
                    action: "reconxFrameworkDetectionResult",
                    result: frameworkDetectionResult
                })
            }
            // ---- 类型 1：路由分析结果 ----
            else if (data.type === 'RECONX_ROUTER_ANALYSIS_RESULT') {
                routerAnalysisResult = data.result as Record<string, unknown>
                // 分析流程结束，释放注入锁
                releaseDetectorLock()

                chrome.runtime.sendMessage({
                    action: "reconxRouterAnalysisResult",
                    result: routerAnalysisResult
                })
            }
            // ---- 类型 1：路由分析出错 ----
            else if (data.type === 'RECONX_ROUTER_ANALYSIS_ERROR') {
                releaseDetectorLock()
                chrome.runtime.sendMessage({
                    action: "reconxRouterAnalysisError",
                    error: data.error
                })
            }
            // ---- 类型 2：梭哈模式状态上报 ----
            else if (data.type === 'RECONX_ALL_IN_STATUS' && data.source === 'reconx-all-in') {
                chrome.runtime.sendMessage({
                    action: "reconxAllInStatus",
                    status: data.status
                })
            }
            // ---- 类型 3：API 提取进度 ----
            else if (data.type === 'RECONX_API_EXTRACT_PROGRESS' && data.source === 'reconx-api-extractor') {
                chrome.runtime.sendMessage({
                    action: "reconxApiProgress",
                    message: data.message
                })
            }
            // ---- 类型 3：API 提取结果 ----
            else if (data.type === 'RECONX_API_EXTRACT_RESULT' && data.source === 'reconx-api-extractor') {
                chrome.runtime.sendMessage({
                    action: "reconxApiResult",
                    result: data.result
                })
            }
            // ---- 类型 3：API 提取出错 ----
            else if (data.type === 'RECONX_API_EXTRACT_ERROR' && data.source === 'reconx-api-extractor') {
                chrome.runtime.sendMessage({
                    action: "reconxApiError",
                    error: data.error
                })
            }
        } catch (e) {
            console.error("Message handling error:", e)
        }
    })

    /**
     * 监听来自 popup/background 的指令并分发处理。
     *
     * 支持的动作：
     *   - detectFramework  ：执行框架检测（有缓存且未强制刷新时直接返回缓存）
     *   - analyzeRouter   ：执行路由分析（有缓存且未强制刷新时直接返回缓存）
     *   - getAllInStatus   ：向页面查询梭哈模式的实时拦截统计
     *   - extractApi       ：注入 API 提取器并开始提取
     *
     * 始终返回 true 以保持消息通道开放，允许后续异步 sendResponse。
     * （popup 不依赖返回值，结果统一通过 chrome.runtime.sendMessage 主动推送）
     */
    chrome.runtime.onMessage.addListener(function (request: Record<string, unknown>, _sender: chrome.runtime.MessageSender, sendResponse: (response?: unknown) => void) {
        try {
            if (request.action === "detectFramework") {
                // 已有检测结果且不要求强制刷新时，直接回传缓存
                if (frameworkDetectionResult.detected && !request.forceRefresh) {
                    chrome.runtime.sendMessage({
                        action: "reconxFrameworkDetectionResult",
                        result: frameworkDetectionResult
                    })
                    sendResponse({ status: "cached" })
                    return true
                }

                sendResponse({ status: "detecting" })
                injectDetector()
            }
            else if (request.action === "analyzeRouter") {
                // 已有分析结果且不要求强制刷新时，直接回传缓存
                if (routerAnalysisResult && !request.forceRefresh) {
                    chrome.runtime.sendMessage({
                        action: "reconxRouterAnalysisResult",
                        result: routerAnalysisResult
                    })
                } else {
                    injectDetector()
                }
                sendResponse({ status: "analyzing" })
            }
            else if (request.action === "getAllInStatus") {
                // 转发给 all-in.js，由页面脚本回传当前拦截统计
                window.postMessage({
                    type: 'RECONX_GET_ALL_IN_STATUS',
                    source: 'reconx-extension'
                }, '*')
                sendResponse({ status: "requested" })
            }
            else if (request.action === "extractApi") {
                injectApiExtractor()
                sendResponse({ status: "extracting" })
            }
        } catch (e) {
            console.error("Request handling error:", e)
            sendResponse({ status: "error", error: String(e) })
        }
        return true
    })
})()