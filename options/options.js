/* global chrome */
(async function () {
  const $ = (id) => document.getElementById(id);
  const DEFAULTS = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5 };

  function parseInput(raw) {
    raw = (raw || "").trim();
    if (!raw) return null;
    if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
    try {
      const u = new URL(raw);
      if (!/^https?:$/.test(u.protocol)) return null;
      return { host: u.hostname, origin: u.protocol + "//" + u.host + "/*" };
    } catch (e) {
      return null;
    }
  }

  function renderScope(scope) {
    const list = $("hostList");
    list.replaceChildren();
    const hosts = (scope && scope.hosts) || [];
    if (!hosts.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "（白名单为空）";
      list.appendChild(li);
    }
    hosts.forEach((h) => {
      const li = document.createElement("li");
      const b = document.createElement("b");
      b.textContent = h.host;
      const meta = document.createElement("span");
      meta.className = "muted";
      meta.textContent = "  加入于 " + new Date(h.addedAt || Date.now()).toLocaleString() + (h.note ? " · " + h.note : "");
      const btn = document.createElement("button");
      btn.className = "danger tiny";
      btn.textContent = "移除并撤销";
      btn.addEventListener("click", async () => {
        try {
          if (h.origin) await chrome.permissions.remove({ origins: [h.origin] });
        } catch (e) {}
        const cur = await getScope();
        cur.hosts = cur.hosts.filter((x) => x.host !== h.host);
        await chrome.storage.local.set({ scope: cur });
        await refresh();
      });
      li.appendChild(b);
      li.appendChild(meta);
      li.appendChild(btn);
      list.appendChild(li);
    });
  }

  async function getScope() {
    const { scope } = await chrome.storage.local.get("scope");
    return scope && Array.isArray(scope.hosts) ? scope : { hosts: [] };
  }

  function renderPerms(origins) {
    const list = $("permList");
    list.replaceChildren();
    if (!origins.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "（无已授予的主机权限）";
      list.appendChild(li);
    }
    origins.forEach((o) => {
      const li = document.createElement("li");
      li.textContent = o;
      list.appendChild(li);
    });
  }

  function renderSettings(s) {
    $("activeProbe").checked = !!s.activeProbe;
    $("maxJsFiles").value = s.maxJsFiles || DEFAULTS.maxJsFiles;
    $("maxConcurrent").value = s.maxConcurrent || DEFAULTS.maxConcurrent;
  }

  async function refresh() {
    const scope = await getScope();
    const { settings } = await chrome.storage.local.get("settings");
    renderScope(scope);
    renderSettings(Object.assign({}, DEFAULTS, settings || {}));
    const perms = await chrome.permissions.getAll();
    renderPerms(perms.origins || []);
  }

  $("addForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("addMsg");
    msg.textContent = "";
    const parsed = parseInput($("hostInput").value);
    if (!parsed) {
      msg.textContent = "无法解析，请输入域名或 URL。";
      return;
    }
    const granted = await chrome.permissions.request({ origins: [parsed.origin] });
    if (!granted) {
      msg.textContent = "未授予权限。";
      return;
    }
    const cur = await getScope();
    if (!cur.hosts.some((h) => h.host === parsed.host)) {
      cur.hosts.push({ host: parsed.host, origin: parsed.origin, addedAt: Date.now(), note: "options 添加" });
      await chrome.storage.local.set({ scope: cur });
    }
    $("hostInput").value = "";
    msg.textContent = "已加入 " + parsed.host + "。";
    await refresh();
  });

  $("save").addEventListener("click", async () => {
    const settings = {
      activeProbe: $("activeProbe").checked,
      maxJsFiles: Math.max(1, parseInt($("maxJsFiles").value, 10) || DEFAULTS.maxJsFiles),
      maxConcurrent: Math.max(1, Math.min(10, parseInt($("maxConcurrent").value, 10) || DEFAULTS.maxConcurrent)),
    };
    await chrome.storage.local.set({ settings });
    $("saveMsg").textContent = "已保存。";
    setTimeout(() => ($("saveMsg").textContent = ""), 1500);
  });

  $("revokeAll").addEventListener("click", async () => {
    const perms = await chrome.permissions.getAll();
    if ((perms.origins || []).length) await chrome.permissions.remove({ origins: perms.origins });
    await chrome.storage.local.set({ scope: { hosts: [] } });
    await refresh();
  });

  await refresh();
})();
