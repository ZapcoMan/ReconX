(function() {
  (function() {
    const INSTALL_KEY = "__RECONX_ALL_IN_INSTALLED__";
    const STATE_KEY = "__RECONX_ALL_IN_STATE__";
    const globalWindow = window;
    if (globalWindow[INSTALL_KEY]) {
      return;
    }
    try {
      Object.defineProperty(window, INSTALL_KEY, {
        value: true,
        configurable: false,
        writable: false
      });
    } catch (error) {
      return;
    }
    const patchedRouters = /* @__PURE__ */ new WeakSet();
    const patchedObjects = /* @__PURE__ */ new WeakSet();
    const originalArrayPush = Array.prototype.push;
    const originalHistory = {
      back: history.back,
      forward: history.forward,
      go: history.go
    };
    const state = {
      injected: true,
      injectedAt: Date.now(),
      routersPatched: 0,
      guardRegistrationBlocked: 0,
      routerJumpBlocked: 0,
      browserJumpBlocked: 0,
      lastEvent: "已前置注入"
    };
    globalWindow[STATE_KEY] = state;
    function getStatus() {
      return {
        injected: state.injected,
        injectedAt: state.injectedAt,
        routersPatched: state.routersPatched,
        guardRegistrationBlocked: state.guardRegistrationBlocked,
        routerJumpBlocked: state.routerJumpBlocked,
        browserJumpBlocked: state.browserJumpBlocked,
        lastEvent: state.lastEvent
      };
    }
    function emitStatus() {
      try {
        window.postMessage({
          type: "RECONX_ALL_IN_STATUS",
          source: "reconx-all-in",
          status: getStatus()
        }, "*");
      } catch (error) {
      }
    }
    function mark(eventName) {
      state.lastEvent = eventName;
      emitStatus();
    }
    function defineValue(target, key, value) {
      try {
        Object.defineProperty(target, key, {
          value,
          configurable: true,
          writable: true
        });
        return true;
      } catch (error) {
        try {
          target[key] = value;
          return true;
        } catch (innerError) {
          return false;
        }
      }
    }
    function maskToString(fn, name) {
      try {
        defineValue(fn, "toString", function() {
          return `function ${name}() { [native code] }`;
        });
      } catch (error) {
      }
    }
    function makeGuardBlocker(name) {
      const blocker = function(..._args) {
        state.guardRegistrationBlocked += 1;
        mark(`已拦截 ${name}`);
        return function removeBlockedGuard() {
        };
      };
      maskToString(blocker, name);
      return blocker;
    }
    function makeRouterJumpBlocker(name) {
      const blocker = function(..._args) {
        state.routerJumpBlocked += 1;
        mark(`已拦截 router.${name}`);
        if (name === "push" || name === "replace") {
          return Promise.resolve(false);
        }
        return void 0;
      };
      maskToString(blocker, name);
      return blocker;
    }
    function makeBrowserJumpBlocker(name) {
      const blocker = function(..._args) {
        state.browserJumpBlocked += 1;
        mark(`已拦截 ${name}`);
        return void 0;
      };
      maskToString(blocker, name.split(".").pop());
      return blocker;
    }
    function isAuthTrue(value) {
      return value === true || value === "true" || value === 1 || value === "1";
    }
    function patchRouteMeta(route) {
      if (!route || typeof route !== "object") {
        return;
      }
      if (route.meta && typeof route.meta === "object") {
        const meta = route.meta;
        Object.keys(meta).forEach((key) => {
          const lowerKey = key.toLowerCase();
          if ((lowerKey.includes("auth") || lowerKey.includes("login") || lowerKey.includes("permission")) && isAuthTrue(meta[key])) {
            meta[key] = false;
          }
        });
      }
      if (Array.isArray(route.children)) {
        route.children.forEach(patchRouteMeta);
      }
    }
    function patchRoutes(router) {
      try {
        if (typeof router.getRoutes === "function") {
          router.getRoutes().forEach(patchRouteMeta);
        }
        if (Array.isArray(router.options?.routes)) {
          router.options.routes.forEach(patchRouteMeta);
        }
        if (Array.isArray(router.matcher?.getRoutes?.())) {
          router.matcher.getRoutes().forEach(patchRouteMeta);
        }
      } catch (error) {
      }
    }
    function clearGuardContainer(value) {
      try {
        if (Array.isArray(value)) {
          value.length = 0;
          return true;
        }
        if (value instanceof Set || value instanceof Map) {
          value.clear();
          return true;
        }
        if (value && typeof value === "object") {
          const container = value;
          if (Array.isArray(container.list)) {
            container.list.length = 0;
            return true;
          }
          if (typeof container.reset === "function") {
            container.reset();
            return true;
          }
        }
      } catch (error) {
        return false;
      }
      return false;
    }
    function clearKnownGuardContainers(router) {
      [
        "beforeGuards",
        "beforeResolveGuards",
        "afterGuards",
        "beforeHooks",
        "resolveHooks",
        "afterHooks",
        "beforeEachHooks",
        "beforeResolveHooks",
        "afterEachHooks"
      ].forEach((key) => clearGuardContainer(router[key]));
    }
    function patchRouter(router) {
      if (!router || typeof router !== "object" || patchedRouters.has(router)) {
        return false;
      }
      patchedRouters.add(router);
      const target = router;
      ["beforeEach", "beforeResolve", "afterEach"].forEach((name) => {
        if (typeof target[name] === "function") {
          defineValue(target, name, makeGuardBlocker(name));
        }
      });
      ["push", "replace", "go"].forEach((name) => {
        if (typeof target[name] === "function") {
          defineValue(target, name, makeRouterJumpBlocker(name));
        }
      });
      clearKnownGuardContainers(target);
      patchRoutes(target);
      state.routersPatched += 1;
      mark("已接管 Router");
      return true;
    }
    function patchVueRouterPrototype() {
      try {
        const proto = window.VueRouter?.prototype;
        if (!proto || patchedObjects.has(proto)) {
          return;
        }
        patchedObjects.add(proto);
        ["beforeEach", "beforeResolve", "afterEach"].forEach((name) => {
          if (typeof proto[name] === "function") {
            defineValue(proto, name, makeGuardBlocker(name));
          }
        });
        ["push", "replace", "go"].forEach((name) => {
          if (typeof proto[name] === "function") {
            defineValue(proto, name, makeRouterJumpBlocker(name));
          }
        });
      } catch (error) {
      }
    }
    function findVueRouterFromElement(element) {
      try {
        if (element.__vue_app__) {
          const app = element.__vue_app__;
          return app.config?.globalProperties?.$router || app._instance?.appContext?.config?.globalProperties?.$router || app._instance?.ctx?.$router || null;
        }
        if (element.__vue__) {
          const vue = element.__vue__;
          return vue.$router || vue.$root?.$router || vue.$root?.$options?.router || vue._router || null;
        }
      } catch (error) {
        return null;
      }
      return null;
    }
    function patchReactRouter(router) {
      if (!router || typeof router !== "object" || patchedRouters.has(router)) {
        return false;
      }
      const target = router;
      if (typeof target.navigate !== "function") {
        return false;
      }
      patchedRouters.add(router);
      const blocker = function(..._args) {
        state.routerJumpBlocked += 1;
        mark("已拦截 router.navigate");
        return Promise.resolve(false);
      };
      maskToString(blocker, "navigate");
      defineValue(target, "navigate", blocker);
      state.routersPatched += 1;
      mark("已接管 React Router");
      return true;
    }
    function patchNextRouter() {
      try {
        const router = window.next?.router;
        if (!router || typeof router !== "object" || patchedRouters.has(router)) {
          return false;
        }
        if (typeof router.push !== "function" && typeof router.replace !== "function") {
          return false;
        }
        patchedRouters.add(router);
        ["push", "replace"].forEach((name) => {
          if (typeof router[name] !== "function") {
            return;
          }
          const blocker = function(..._args) {
            state.routerJumpBlocked += 1;
            mark(`已拦截 next.router.${name}`);
            return Promise.resolve(false);
          };
          maskToString(blocker, name);
          defineValue(router, name, blocker);
        });
        state.routersPatched += 1;
        mark("已接管 Next.js Router");
        return true;
      } catch (error) {
        return false;
      }
    }
    function findReactKey(element, prefix) {
      for (const key in element) {
        if (key.indexOf(prefix) === 0) {
          return key;
        }
      }
      return "";
    }
    function isReactRouterLike(candidate) {
      if (!candidate || typeof candidate !== "object") {
        return false;
      }
      const obj = candidate;
      if (typeof obj.navigate !== "function" || !(obj.state && typeof obj.state === "object")) {
        return false;
      }
      return Array.isArray(obj.routes) || !!obj.state?.location || !!obj.state?.matches || !!obj.options;
    }
    function findReactRouterFromElement(element) {
      try {
        let rootFiber = null;
        const containerKey = findReactKey(element, "__reactContainer");
        if (containerKey) {
          const container = element[containerKey];
          rootFiber = container?.current || container || null;
        }
        if (!rootFiber && element._reactRootContainer) {
          const internalRoot = element._reactRootContainer._internalRoot;
          rootFiber = internalRoot?.current || null;
        }
        if (!rootFiber) {
          const fiberKey = findReactKey(element, "__reactFiber");
          if (fiberKey) {
            let fiber = element[fiberKey];
            while (fiber && fiber.return) {
              fiber = fiber.return;
            }
            rootFiber = fiber;
          }
        }
        if (!rootFiber) {
          return null;
        }
        const queue = [rootFiber];
        const visited = /* @__PURE__ */ new Set();
        let scanned = 0;
        const pick = (...candidates) => {
          for (const candidate of candidates) {
            if (isReactRouterLike(candidate)) return candidate;
            if (candidate && typeof candidate === "object") {
              const wrapped = candidate.router;
              if (isReactRouterLike(wrapped)) return wrapped;
            }
          }
          return null;
        };
        while (queue.length && scanned < 6e3) {
          const fiber = queue.shift();
          if (!fiber || visited.has(fiber)) continue;
          visited.add(fiber);
          scanned += 1;
          const found = pick(
            fiber.memoizedProps,
            fiber.memoizedProps?.router,
            fiber.stateNode
          );
          if (found) return found;
          let hook = fiber.memoizedState;
          let guard = 0;
          while (hook && guard < 100) {
            const viaHook = pick(hook.memoizedState);
            if (viaHook) return viaHook;
            hook = hook.next;
            guard += 1;
          }
          if (fiber.child) queue.push(fiber.child);
          if (fiber.sibling) queue.push(fiber.sibling);
        }
      } catch (error) {
        return null;
      }
      return null;
    }
    function scanRouters() {
      patchVueRouterPrototype();
      patchNextRouter();
      if (!document.documentElement) {
        return;
      }
      const queue = [document.documentElement];
      const visited = /* @__PURE__ */ new Set();
      let scanned = 0;
      while (queue.length && scanned < 8e3) {
        const node = queue.shift();
        scanned += 1;
        if (!node || visited.has(node)) {
          continue;
        }
        visited.add(node);
        if (node.nodeType === 1) {
          const element = node;
          const vueRouter = findVueRouterFromElement(element);
          if (vueRouter) {
            patchRouter(vueRouter);
          } else {
            const reactRouter = findReactRouterFromElement(element);
            if (reactRouter) {
              patchReactRouter(reactRouter);
            }
          }
          if (node.childNodes && node.childNodes.length) {
            for (let i = 0; i < node.childNodes.length; i++) {
              queue.push(node.childNodes[i]);
            }
          }
        }
      }
    }
    function installArrayPushGuardBlocker() {
      const hookedPush = function(...args) {
        if (args.length > 0 && typeof args[0] === "function") {
          try {
            const stack = new Error().stack || "";
            if (stack.includes("beforeEach") || stack.includes("beforeResolve") || stack.includes("afterEach")) {
              state.guardRegistrationBlocked += 1;
              mark("已阻止守卫注册");
              return originalArrayPush.call(this);
            }
          } catch (error) {
          }
        }
        return originalArrayPush.apply(this, args);
      };
      maskToString(hookedPush, "push");
      defineValue(Array.prototype, "push", hookedPush);
    }
    function installBrowserJumpBlockers() {
      if (typeof history.back === "function") {
        defineValue(history, "back", makeBrowserJumpBlocker("history.back"));
      }
      if (typeof history.forward === "function") {
        defineValue(history, "forward", makeBrowserJumpBlocker("history.forward"));
      }
      if (typeof history.go === "function") {
        defineValue(history, "go", makeBrowserJumpBlocker("history.go"));
      }
      try {
        const locationPrototype = Location.prototype;
        if (typeof locationPrototype.assign === "function") {
          defineValue(locationPrototype, "assign", makeBrowserJumpBlocker("location.assign"));
        }
        if (typeof locationPrototype.replace === "function") {
          defineValue(locationPrototype, "replace", makeBrowserJumpBlocker("location.replace"));
        }
      } catch (error) {
      }
      if (typeof window.close === "function") {
        defineValue(window, "close", makeBrowserJumpBlocker("window.close"));
      }
    }
    let scanTimer = null;
    function scheduleScan(delay) {
      if (scanTimer) {
        return;
      }
      scanTimer = setTimeout(() => {
        scanTimer = null;
        scanRouters();
      }, delay);
    }
    function startObserver() {
      if (!document.documentElement || typeof MutationObserver !== "function") {
        return;
      }
      const observer = new MutationObserver(() => {
        scheduleScan(80);
      });
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }
    window.addEventListener("message", (event) => {
      if (event.source !== window || !event.data) {
        return;
      }
      if (event.data.type === "reconx_GET_ALL_IN_STATUS") {
        emitStatus();
      }
    });
    installArrayPushGuardBlocker();
    installBrowserJumpBlockers();
    emitStatus();
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        scanRouters();
        startObserver();
      });
    } else {
      scanRouters();
      startObserver();
    }
    [50, 150, 350, 800, 1500, 3e3, 6e3].forEach((delay) => {
      setTimeout(scanRouters, delay);
    });
  })();
})();
