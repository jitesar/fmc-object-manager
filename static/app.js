const state = {
  user: null,
  view: "dashboard",
  lang: localStorage.getItem("fmcObjectManager.lang") || "cs",
  busy: { sync: false, refreshId: null },
  objectFilters: { q: "", type: "", source: "" },
  overridableFilters: { q: "", type: "" },
  objectSort: { key: "name", direction: "asc" },
  selectedObjectId: null,
  objectDetailTab: "global",
  cache: {},
  debug: {
    enabled: localStorage.getItem("fmcObjectManager.debug") === "1",
    filterText: localStorage.getItem("fmcObjectManager.debugFilter") || "",
    onlyMatches: localStorage.getItem("fmcObjectManager.debugOnlyMatches") === "1",
    logs: [],
    nextId: 1,
  },
};

const roleLevel = { viewer: 10, operator: 20, approver: 30, admin: 40 };
const NETWORK_TYPES = ["Host", "Network", "Range", "FQDN", "NetworkGroup"];
const PORT_TYPES = ["ProtocolPortObject", "PortGroup"];
const PORT_OBJECT_TYPES = ["ProtocolPortObject", "ICMPV4Object", "ICMPV6Object"];

const I18N = {
  cs: {
    dashboard: "Dashboard",
    objects: "Objekty",
    overridableObjects: "Overridable objekty",
    changes: "Změny",
    audit: "Audit",
    users: "Uživatelé",
    settings: "Nastavení",
    changePassword: "Změnit heslo",
    logout: "Odhlásit",
    appSubtitle: "Lokální správa, audit a FMC REST API konektor",
    username: "Uživatelské jméno",
    password: "Heslo",
    login: "Přihlásit",
    objectCount: "Objekty",
    overrideCount: "Override",
    pendingChanges: "Pending změny",
    activeUsers: "Aktivní uživatelé",
    objectTypes: "Typy objektů",
    type: "Typ",
    count: "Počet",
    fmcConnector: "FMC konektor",
    user: "Uživatel",
    notConfigured: "nenastaveno",
    unknown: "neznámý",
    enabled: "zapnuto",
    recentAudit: "Poslední audit",
    syncFmc: "Sync z FMC",
    syncing: "Synchronizuji...",
    newObject: "Nový objekt",
    search: "Hledat",
    allTypes: "Všechny typy",
    allStates: "Všechny stavy",
    trulyInFmc: "Skutečně ve FMC",
    localUnpushed: "Lokální / nepropsané",
    localOnly: "Jen lokální nové",
    locallyChanged: "Lokálně změněné",
    missingInFmc: "Nenalezeno ve FMC",
    name: "Název",
    value: "Hodnota",
    state: "Stav",
    overrideAllowed: "Override povolen",
    noObject: "Žádný objekt",
    selectObject: "Vyberte objekt",
    refreshFmc: "Refresh z FMC",
    refreshing: "Načítám...",
    edit: "Upravit",
    delete: "Smazat",
    global: "Global",
    usage: "Usage",
    history: "History",
    local: "lokální",
    localObject: "lokální",
    globalValue: "Globální hodnota",
    lastSync: "Poslední sync",
    description: "Popis",
    yes: "ano",
    no: "ne",
    close: "Zavřít",
    save: "Uložit",
    action: "Akce",
    addObject: "Add Object",
    importObject: "Import Object",
    addGroup: "Add Group",
    portObjects: "Port objekty",
    networkObjects: "Network objekty",
    groupName: "Název skupiny",
    originalValue: "Původní hodnota objektu",
    overrideValue: "Override hodnota",
    overrideVariants: "Override varianty",
    noOverridableObjects: "Žádné overridable objekty",
    noOverrideVariants: "Bez override variant",
    originalVsOverrides: "Originální hodnoty a override varianty",
    targetFw: "Target FW",
    targetId: "Target ID",
    noOverrides: "Bez override",
    objectSavedFmc: "Objekt uložen do FMC a lokální cache.",
    objectSavedLocal: "Objekt uložen lokálně.",
    overrideSaved: "Override uložen.",
    overrideSavedFmc: "Override uložen do FMC.",
    overrideSavedLocal: "Override uložen lokálně.",
    deleteOverrideValue: "Smazat override hodnotu",
    confirmDeleteOverrideValue: "Smazat override hodnotu pro tento target FW?",
    overrideDeleted: "Override hodnota smazána z lokální evidence.",
    overrideDeletedFmc: "Override hodnota smazána z FMC i lokální evidence.",
    syncDone: "Sync hotový",
    refreshDone: "Objekt a override tabulka načteny z FMC.",
    importCsvFile: "Import CSV souboru",
    browse: "Browse...",
    importCsv: "Importovat CSV",
    importNetworkObjects: "Import Network objektů",
    importPortObjects: "Import Port objektů",
    csvHeaderMandatory: "Hlavička sloupců je povinná.",
    csvHeaderUppercase: "Hlavička musí být velkými písmeny.",
    sampleData: "Ukázková data:",
    csvImported: "CSV import dokončen",
    apiDebug: "API debug",
    apiDebugEmpty: "Zatím žádná API volání.",
    clearDebug: "Vyčistit",
    debugFilter: "Filtr objektu",
    debugFilterPlaceholder: "ID, název, FMC ID nebo hodnota",
    debugCurrentObject: "Aktuální objekt",
    debugOnlyMatches: "Jen shody",
    debugMatches: "shod",
    request: "Request",
    response: "Response",
    duration: "Doba",
  },
  en: {
    dashboard: "Dashboard",
    objects: "Objects",
    overridableObjects: "Overridable objects",
    changes: "Changes",
    audit: "Audit",
    users: "Users",
    settings: "Settings",
    changePassword: "Change password",
    logout: "Sign out",
    appSubtitle: "Local management, audit, and FMC REST API connector",
    username: "Username",
    password: "Password",
    login: "Sign in",
    objectCount: "Objects",
    overrideCount: "Overrides",
    pendingChanges: "Pending changes",
    activeUsers: "Active users",
    objectTypes: "Object types",
    type: "Type",
    count: "Count",
    fmcConnector: "FMC connector",
    user: "User",
    notConfigured: "not configured",
    unknown: "unknown",
    enabled: "enabled",
    recentAudit: "Recent audit",
    syncFmc: "Sync from FMC",
    syncing: "Syncing...",
    newObject: "New object",
    search: "Search",
    allTypes: "All types",
    allStates: "All states",
    trulyInFmc: "Really in FMC",
    localUnpushed: "Local / not pushed",
    localOnly: "Only local new",
    locallyChanged: "Locally changed",
    missingInFmc: "Missing in FMC",
    name: "Name",
    value: "Value",
    state: "State",
    overrideAllowed: "Override allowed",
    noObject: "No object",
    selectObject: "Select an object",
    refreshFmc: "Refresh from FMC",
    refreshing: "Refreshing...",
    edit: "Edit",
    delete: "Delete",
    global: "Global",
    usage: "Usage",
    history: "History",
    local: "local",
    localObject: "local",
    globalValue: "Global value",
    lastSync: "Last sync",
    description: "Description",
    yes: "yes",
    no: "no",
    close: "Close",
    save: "Save",
    action: "Action",
    addObject: "Add Object",
    importObject: "Import Object",
    addGroup: "Add Group",
    portObjects: "Port objects",
    networkObjects: "Network objects",
    groupName: "Group name",
    originalValue: "Original object value",
    overrideValue: "Override value",
    overrideVariants: "Override variants",
    noOverridableObjects: "No overridable objects",
    noOverrideVariants: "No override variants",
    originalVsOverrides: "Original values and override variants",
    targetFw: "Target FW",
    targetId: "Target ID",
    noOverrides: "No overrides",
    objectSavedFmc: "Object saved to FMC and local cache.",
    objectSavedLocal: "Object saved locally.",
    overrideSaved: "Override saved.",
    overrideSavedFmc: "Override saved to FMC.",
    overrideSavedLocal: "Override saved locally.",
    deleteOverrideValue: "Delete override value",
    confirmDeleteOverrideValue: "Delete the override value for this target FW?",
    overrideDeleted: "Override value deleted from local records.",
    overrideDeletedFmc: "Override value deleted from FMC and local records.",
    syncDone: "Sync finished",
    refreshDone: "Object and override table refreshed from FMC.",
    importCsvFile: "Import CSV file",
    browse: "Browse...",
    importCsv: "Import CSV",
    importNetworkObjects: "Import Network Objects",
    importPortObjects: "Import Port Objects",
    csvHeaderMandatory: "Column header is mandatory.",
    csvHeaderUppercase: "Column header should be in capital letters.",
    sampleData: "Sample data:",
    csvImported: "CSV import finished",
    apiDebug: "API debug",
    apiDebugEmpty: "No API calls yet.",
    clearDebug: "Clear",
    debugFilter: "Object filter",
    debugFilterPlaceholder: "ID, name, FMC ID, or value",
    debugCurrentObject: "Current object",
    debugOnlyMatches: "Only matches",
    debugMatches: "matches",
    request: "Request",
    response: "Response",
    duration: "Duration",
  },
};

function t(key) {
  return I18N[state.lang]?.[key] || I18N.cs[key] || key;
}

function setLanguage(lang) {
  state.lang = lang;
  localStorage.setItem("fmcObjectManager.lang", lang);
  render();
}

function langToggle() {
  return `
    <div class="lang-toggle" role="group" aria-label="Language">
      <button class="${state.lang === "cs" ? "active" : ""}" onclick="setLanguage('cs')" type="button">CS</button>
      <button class="${state.lang === "en" ? "active" : ""}" onclick="setLanguage('en')" type="button">EN</button>
    </div>
  `;
}

function can(role) {
  return state.user && roleLevel[state.user.role] >= roleLevel[role];
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function redactDebugValue(value, key = "") {
  const sensitive = /(password|passwd|token|secret|authorization|cookie|session)/i.test(key);
  if (sensitive && value !== undefined && value !== null && value !== "") return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => redactDebugValue(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([itemKey, itemValue]) => [itemKey, redactDebugValue(itemValue, itemKey)]));
  }
  return value;
}

function debugJson(value) {
  if (value === undefined) return "";
  if (value === null) return "null";
  return JSON.stringify(redactDebugValue(value), null, 2);
}

function startDebugApiCall(method, path, body) {
  if (!state.debug.enabled) return null;
  const entry = {
    id: state.debug.nextId,
    method,
    path,
    request: redactDebugValue(body ?? null),
    response: null,
    status: "pending",
    ok: null,
    error: "",
    startedAt: new Date().toLocaleTimeString("cs-CZ"),
    durationMs: null,
  };
  state.debug.nextId += 1;
  state.debug.logs.unshift(entry);
  state.debug.logs = state.debug.logs.slice(0, 80);
  renderDebugPanel();
  return entry.id;
}

function finishDebugApiCall(id, patch) {
  if (!id) return;
  const entry = state.debug.logs.find((item) => item.id === id);
  if (!entry) return;
  Object.assign(entry, patch);
  renderDebugPanel();
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const started = performance.now();
  const debugId = startDebugApiCall(method, path, options.body);
  try {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = response.status === 204 ? null : await response.json().catch(() => ({}));
    finishDebugApiCall(debugId, {
      response: redactDebugValue(data),
      status: response.status,
      ok: response.ok,
      durationMs: Math.round(performance.now() - started),
    });
    if (response.status === 204) return null;
    if (!response.ok) {
      const message = data.details ? `${data.error}: ${data.details}` : data.error || "Chyba pozadavku";
      throw new Error(message);
    }
    return data;
  } catch (error) {
    const entry = state.debug.logs.find((item) => item.id === debugId);
    if (entry && entry.status !== "pending") {
      entry.error = error.message;
      renderDebugPanel();
    } else {
      finishDebugApiCall(debugId, {
        response: null,
        status: "error",
        ok: false,
        error: error.message,
        durationMs: Math.round(performance.now() - started),
      });
    }
    throw error;
  }
}

function app() {
  return document.getElementById("app");
}

function setView(view) {
  state.view = view;
  render();
}

function notify(message, type = "success") {
  const holder = document.querySelector("[data-flash]");
  if (!holder) return;
  holder.innerHTML = `<div class="${type}">${escapeHtml(message)}</div>`;
  window.setTimeout(() => {
    if (holder) holder.innerHTML = "";
  }, 4200);
}

function toggleDebug(enabled) {
  state.debug.enabled = Boolean(enabled);
  localStorage.setItem("fmcObjectManager.debug", state.debug.enabled ? "1" : "0");
  render();
}

function clearDebugLogs() {
  state.debug.logs = [];
  renderDebugPanel();
}

function debugFilterTokens() {
  return String(state.debug.filterText || "")
    .split(/\s+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function selectedDebugObject() {
  return (state.cache.objects || []).find((item) => String(item.id) === String(state.selectedObjectId)) || null;
}

function selectedDebugObjectFilter() {
  const item = selectedDebugObject();
  if (!item) return "";
  return [
    item.id,
    item.fmc_id,
    item.name,
    item.value,
    item.display_value,
  ].filter(Boolean).join(" ");
}

function debugEntryText(entry) {
  return [
    entry.method,
    entry.path,
    entry.status,
    entry.error,
    debugJson(entry.request),
    debugJson(entry.response),
  ].join("\n").toLowerCase();
}

function debugEntryMatches(entry) {
  const tokens = debugFilterTokens();
  if (!tokens.length) return false;
  const text = debugEntryText(entry);
  return tokens.some((token) => text.includes(token));
}

function filteredDebugLogs() {
  const tokens = debugFilterTokens();
  if (!tokens.length || !state.debug.onlyMatches) return state.debug.logs;
  return state.debug.logs.filter((entry) => debugEntryMatches(entry));
}

function setDebugFilter(value) {
  state.debug.filterText = value || "";
  localStorage.setItem("fmcObjectManager.debugFilter", state.debug.filterText);
  refreshDebugList();
}

function useSelectedDebugObject() {
  setDebugFilter(selectedDebugObjectFilter());
  renderDebugPanel();
}

function toggleDebugOnlyMatches(enabled) {
  state.debug.onlyMatches = Boolean(enabled);
  localStorage.setItem("fmcObjectManager.debugOnlyMatches", state.debug.onlyMatches ? "1" : "0");
  refreshDebugList();
}

function refreshDebugList() {
  const list = document.querySelector("[data-debug-list]");
  if (!list) return;
  const items = filteredDebugLogs();
  const matches = state.debug.logs.filter((entry) => debugEntryMatches(entry)).length;
  const count = document.querySelector("[data-debug-count]");
  if (count) {
    count.textContent = `${state.debug.logs.length} ${state.lang === "en" ? "calls" : "volání"} · ${matches} ${t("debugMatches")}`;
  }
  list.innerHTML = items.map((entry, index) => debugEntry(entry, index === 0)).join("") || `<div class="empty">${t("apiDebugEmpty")}</div>`;
}

function renderDebugPanel() {
  const holder = document.getElementById("debug-panel");
  if (!holder) return;
  holder.innerHTML = debugPanel();
}

function debugPanel() {
  if (!state.debug.enabled) return "";
  return `
    <div class="panel debug-panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">${t("apiDebug")}</div>
          <div class="muted" data-debug-count>${state.debug.logs.length} ${state.lang === "en" ? "calls" : "volání"} · ${state.debug.logs.filter((entry) => debugEntryMatches(entry)).length} ${t("debugMatches")}</div>
        </div>
        <button type="button" onclick="clearDebugLogs()">${t("clearDebug")}</button>
      </div>
      <div class="debug-tools">
        <label>${t("debugFilter")}
          <input class="mono" value="${escapeHtml(state.debug.filterText)}" placeholder="${t("debugFilterPlaceholder")}" oninput="setDebugFilter(this.value)">
        </label>
        <button type="button" onclick="useSelectedDebugObject()" ${selectedDebugObject() ? "" : "disabled"}>${t("debugCurrentObject")}</button>
        <label class="switch"><input type="checkbox" ${state.debug.onlyMatches ? "checked" : ""} onchange="toggleDebugOnlyMatches(this.checked)"> ${t("debugOnlyMatches")}</label>
      </div>
      <div class="debug-list" data-debug-list>
        ${filteredDebugLogs().map((entry, index) => debugEntry(entry, index === 0)).join("") || `<div class="empty">${t("apiDebugEmpty")}</div>`}
      </div>
    </div>
  `;
}

function debugEntry(entry, open) {
  const statusClass = entry.status === "pending" ? "warn" : (entry.ok ? "green" : "red");
  const matches = debugEntryMatches(entry);
  const responseText = entry.error
    ? `${debugJson(entry.response)}\n\nError: ${entry.error}`.trim()
    : debugJson(entry.response);
  return `
    <details class="debug-entry ${matches ? "debug-match" : ""}" ${open ? "open" : ""}>
      <summary>
        <span class="debug-method">${escapeHtml(entry.method)}</span>
        <strong>${escapeHtml(entry.path)}</strong>
        ${matches ? `<span class="pill blue">${t("debugMatches")}</span>` : ""}
        <span class="pill ${statusClass}">${escapeHtml(entry.status)}</span>
        <span class="muted">${entry.durationMs === null ? entry.startedAt : `${t("duration")}: ${entry.durationMs} ms`}</span>
      </summary>
      <div class="debug-body">
        <div>
          <h4>${t("request")}</h4>
          <pre>${escapeHtml(debugJson(entry.request))}</pre>
        </div>
        <div>
          <h4>${t("response")}</h4>
          <pre>${escapeHtml(responseText)}</pre>
        </div>
      </div>
    </details>
  `;
}

async function init() {
  const me = await api("/api/auth/me");
  state.user = me.user;
  render();
}

function render() {
  if (!state.user) {
    renderLogin();
    return;
  }
  app().innerHTML = `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark"><img src="/FMC.png" alt="FMC"></div>
          <div>
            <div class="brand-title">FMC Object Manager</div>
            <div class="brand-subtitle">${escapeHtml(state.user.display_name)} · ${escapeHtml(state.user.role)}</div>
          </div>
        </div>
        <nav class="nav">
          ${navButton("dashboard", t("dashboard"))}
          ${navButton("objects", t("objects"))}
          ${navButton("overridable", t("overridableObjects"))}
          ${navButton("changes", t("changes"))}
          ${navButton("audit", t("audit"))}
          ${can("admin") ? navButton("users", t("users")) : ""}
          ${can("admin") ? navButton("settings", t("settings")) : ""}
        </nav>
        <div class="sidebar-footer">
          ${langToggle()}
          <label class="switch debug-switch"><input type="checkbox" ${state.debug.enabled ? "checked" : ""} onchange="toggleDebug(this.checked)"> ${t("apiDebug")}</label>
          <button class="ghost" onclick="openPasswordModal()">${t("changePassword")}</button>
          <button onclick="logout()">${t("logout")}</button>
        </div>
      </aside>
      <main class="main">
        <header class="topbar">
          <div>
            <div class="page-title">${pageTitle()}</div>
            <div class="muted">${t("appSubtitle")}</div>
          </div>
          <div class="topbar-actions" data-topbar-actions></div>
        </header>
        <section class="content">
          <div data-flash></div>
          <div id="view"></div>
          <div id="debug-panel">${debugPanel()}</div>
        </section>
      </main>
    </div>
  `;
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  if (state.user.force_password_change) openPasswordModal(true);
  renderView();
}

function navButton(view, label) {
  return `<button class="${state.view === view ? "active" : ""}" data-view="${view}">${escapeHtml(label)}</button>`;
}

function pageTitle() {
  return {
    dashboard: "Dashboard",
    objects: t("objects"),
    overridable: t("overridableObjects"),
    changes: t("changes"),
    audit: t("audit"),
    users: t("users"),
    settings: "FMC " + t("settings").toLowerCase(),
  }[state.view] || "FMC Object Manager";
}

function renderView() {
  const topbar = document.querySelector("[data-topbar-actions]");
  if (topbar) topbar.innerHTML = "";
  const views = {
    dashboard: renderDashboard,
    objects: renderObjects,
    overridable: renderOverridableObjects,
    changes: renderChanges,
    audit: renderAudit,
    users: renderUsers,
    settings: renderSettings,
  };
  (views[state.view] || renderDashboard)();
}

function renderLogin(error = "") {
  app().innerHTML = `
    <section class="login-screen">
      <form class="login-box login-form" onsubmit="login(event)">
        <div class="brand">
          <div class="brand-mark"><img src="/FMC.png" alt="FMC"></div>
          <div>
            <div class="brand-title">FMC Object Manager</div>
            <div class="brand-subtitle">https://10.62.8.190</div>
          </div>
        </div>
        ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
        <label>${t("username")}
          <input name="username" autocomplete="username" value="admin" required>
        </label>
        <label>${t("password")}
          <input name="password" type="password" autocomplete="current-password" required>
        </label>
        <button class="primary" type="submit">${t("login")}</button>
      </form>
    </section>
  `;
}

async function login(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: { username: form.get("username"), password: form.get("password") },
    });
    state.user = result.user;
    render();
  } catch (error) {
    renderLogin(error.message);
  }
}

async function logout() {
  await api("/api/auth/logout", { method: "POST" }).catch(() => null);
  state.user = null;
  render();
}

async function renderDashboard() {
  const data = await api("/api/dashboard");
  document.getElementById("view").innerHTML = `
    <div class="metrics">
      ${metric(t("objectCount"), data.counts.objects)}
      ${metric(t("overrideCount"), data.counts.overrides)}
      ${metric(t("pendingChanges"), data.counts.pending_changes)}
      ${metric(t("activeUsers"), data.counts.users)}
    </div>
    <div class="grid-2">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">${t("objectTypes")}</div></div>
        <div class="table-wrap">
          <table class="summary-table">
            <thead><tr><th>${t("type")}</th><th>${t("count")}</th></tr></thead>
            <tbody>${data.object_types.map((row) => `<tr><td>${escapeHtml(objectTypeLabel(row.object_type))}</td><td>${row.count}</td></tr>`).join("")}</tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">${t("fmcConnector")}</div></div>
        <div class="detail">
          <div class="kv">
            <span>Base URL</span><strong>${escapeHtml(data.fmc.base_url)}</strong>
            <span>${t("user")}</span><strong>${escapeHtml(data.fmc.username || t("notConfigured"))}</strong>
            <span>Domain UUID</span><strong class="mono">${escapeHtml(data.fmc.domain_uuid || t("unknown"))}</strong>
            <span>TLS verify</span><strong>${data.fmc.verify_tls ? t("enabled") : "lab-only off"}</strong>
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">${t("recentAudit")}</div></div>
      ${auditTable(data.recent_audit)}
    </div>
  `;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${Number(value).toLocaleString("cs-CZ")}</strong></div>`;
}

function sortHeader(key, label) {
  const active = state.objectSort.key === key;
  const arrow = active ? (state.objectSort.direction === "asc" ? " ^" : " v") : "";
  return `<button class="th-sort ${active ? "active" : ""}" onclick="setObjectSort('${key}')">${escapeHtml(label)}${arrow}</button>`;
}

function setObjectSort(key) {
  if (state.objectSort.key === key) {
    state.objectSort.direction = state.objectSort.direction === "asc" ? "desc" : "asc";
  } else {
    state.objectSort = { key, direction: "asc" };
  }
  renderObjects();
}

function sortedObjects(items) {
  const direction = state.objectSort.direction === "desc" ? -1 : 1;
  const key = state.objectSort.key;
  return [...items].sort((a, b) => {
    let av = objectSortValue(a, key);
    let bv = objectSortValue(b, key);
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * direction;
    av = String(av ?? "").toLocaleLowerCase("cs-CZ");
    bv = String(bv ?? "").toLocaleLowerCase("cs-CZ");
    return av.localeCompare(bv, "cs-CZ", { numeric: true }) * direction;
  });
}

function objectSortValue(item, key) {
  if (key === "override_count") return Number(item.override_count || 0);
  if (key === "overridable") return item.overridable ? 1 : 0;
  if (key === "source") return sourceLabel(item).label;
  if (key === "object_type") return objectTypeLabel(item.object_type);
  if (key === "value") return item.display_value || item.value || "";
  return item[key] || "";
}

function objectTypeLabel(type) {
  if (type === "ProtocolPortObject") return "Port";
  if (type === "ICMPV4Object" || type === "ICMPV6Object") return "Port";
  if (type === "PortGroup") return "Port Group";
  if (type === "NetworkGroup") return "Network Group";
  return type || "";
}

function objectTypeOptions(selectedType = "", includeAll = false) {
  const option = (type) => `<option value="${escapeHtml(type)}" ${selectedType === type ? "selected" : ""}>${escapeHtml(objectTypeLabel(type))}</option>`;
  return `
    ${includeAll ? `<option value="">${t("allTypes")}</option>` : ""}
    <optgroup label="Network">
      ${NETWORK_TYPES.map(option).join("")}
    </optgroup>
    <optgroup label="Port">
      ${PORT_TYPES.map(option).join("")}
    </optgroup>
  `;
}

function sourceLabel(item) {
  const source = item?.source || "local";
  if (source === "fmc") return { label: "FMC", className: "green" };
  if (source === "missing_in_fmc") return { label: t("missingInFmc"), className: "red" };
  if (source === "local_modified") return { label: t("locallyChanged"), className: "warn" };
  if (source === "demo") return { label: `demo ${t("local")}`, className: "" };
  return { label: t("local"), className: "warn" };
}

function sourcePill(item) {
  const source = sourceLabel(item);
  return `<span class="pill ${source.className}">${escapeHtml(source.label)}</span>`;
}

async function renderObjects() {
  const params = new URLSearchParams();
  if (state.objectFilters.q) params.set("q", state.objectFilters.q);
  if (state.objectFilters.type) params.set("type", state.objectFilters.type);
  if (state.objectFilters.source) params.set("source", state.objectFilters.source);
  const data = await api(`/api/objects?${params}`);
  const items = sortedObjects(data.items);
  state.cache.objects = items;
  if (!state.selectedObjectId && items.length) state.selectedObjectId = items[0].id;
  const selected = items.find((item) => item.id === state.selectedObjectId) || items[0];
  if (selected && !["global", "overrides", "usage", "history"].includes(state.objectDetailTab)) state.objectDetailTab = "global";
  const topbar = document.querySelector("[data-topbar-actions]");
  topbar.innerHTML = can("operator") ? `
    <button data-action="sync" onclick="syncFmc()" ${state.busy.sync ? "disabled" : ""}>${state.busy.sync ? `<span class="spinner"></span>${t("syncing")}` : t("syncFmc")}</button>
    <button class="primary" onclick="openObjectModal()">${t("newObject")}</button>
  ` : "";
  document.getElementById("view").innerHTML = `
    <div class="grid-2">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">${t("objects")}</div>
          <div class="toolbar">
            <input id="object-search" placeholder="${t("search")}" value="${escapeHtml(state.objectFilters.q)}">
            <select id="object-type">
              ${objectTypeOptions(state.objectFilters.type, true)}
            </select>
            <select id="object-source">
              <option value="">${t("allStates")}</option>
              <option value="fmc" ${state.objectFilters.source === "fmc" ? "selected" : ""}>${t("trulyInFmc")}</option>
              <option value="local_changes" ${state.objectFilters.source === "local_changes" ? "selected" : ""}>${t("localUnpushed")}</option>
              <option value="local" ${state.objectFilters.source === "local" ? "selected" : ""}>${t("localOnly")}</option>
              <option value="local_modified" ${state.objectFilters.source === "local_modified" ? "selected" : ""}>${t("locallyChanged")}</option>
              <option value="missing_in_fmc" ${state.objectFilters.source === "missing_in_fmc" ? "selected" : ""}>${t("missingInFmc")}</option>
            </select>
          </div>
        </div>
        <div class="table-wrap">
          <table class="object-table">
            <thead><tr>
              <th>${sortHeader("name", t("name"))}</th>
              <th>${sortHeader("object_type", t("type"))}</th>
              <th>${sortHeader("value", t("value"))}</th>
              <th>${sortHeader("source", t("state"))}</th>
              <th>${sortHeader("override_count", "Override")}</th>
              <th>${sortHeader("overridable", t("overrideAllowed"))}</th>
            </tr></thead>
            <tbody>
              ${items.map((item) => `
                <tr class="${selected && String(item.id) === String(selected.id) ? "selected-row" : ""}" onclick="selectObject(${item.id})">
                  <td><strong>${escapeHtml(item.name)}</strong><div class="muted">${escapeHtml(item.description)}</div></td>
                  <td><span class="pill blue">${escapeHtml(objectTypeLabel(item.object_type))}</span></td>
                  <td class="mono">${escapeHtml(item.display_value || item.value)}</td>
                  <td>${sourcePill(item)}</td>
                  <td>${item.override_count ? `<span class="pill green">${item.override_count}</span>` : `<span class="muted">0</span>`}</td>
                  <td>${item.overridable ? `<span class="pill green">${t("yes")}</span>` : `<span class="pill red">${t("no")}</span>`}</td>
                </tr>
              `).join("") || `<tr><td colspan="6"><div class="empty">${t("noObject")}</div></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div id="object-detail">${selected ? objectDetailShell(selected) : `<div class="panel"><div class="empty">${t("selectObject")}</div></div>`}</div>
    </div>
  `;
  document.getElementById("object-search").addEventListener("input", debounce((event) => {
    state.objectFilters.q = event.target.value;
    renderObjects();
  }, 250));
  document.getElementById("object-type").addEventListener("change", (event) => {
    state.objectFilters.type = event.target.value;
    state.selectedObjectId = null;
    renderObjects();
  });
  document.getElementById("object-source").addEventListener("change", (event) => {
    state.objectFilters.source = event.target.value;
    state.selectedObjectId = null;
    renderObjects();
  });
  if (selected) renderObjectTab(selected);
  renderDebugPanel();
}

function objectDetailShell(item) {
  return `
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">${escapeHtml(item.name)}</div>
          <div class="muted">${escapeHtml(objectTypeLabel(item.object_type))} · ${sourceLabel(item).label}</div>
        </div>
        <div class="actions">
          ${item.fmc_id && can("operator") ? `<button data-refresh-id="${item.id}" onclick="refreshObjectFromFmc(${item.id})" ${state.busy.refreshId === item.id ? "disabled" : ""}>${state.busy.refreshId === item.id ? `<span class="spinner"></span>${t("refreshing")}` : t("refreshFmc")}</button>` : ""}
          ${can("operator") ? `<button onclick="openObjectModal(${item.id})">${t("edit")}</button>` : ""}
          ${can("operator") ? `<button class="primary" onclick="openOverrideModal(${item.id})" ${item.overridable ? "" : "disabled"}>Override</button>` : ""}
          ${can("approver") ? `<button class="danger" onclick="deleteObject(${item.id})">${t("delete")}</button>` : ""}
        </div>
      </div>
      <div class="tabs">
        ${detailTabButton("global", t("global"))}
        ${detailTabButton("overrides", "Overrides")}
        ${detailTabButton("usage", t("usage"))}
        ${detailTabButton("history", t("history"))}
      </div>
      <div id="object-tab-content">${objectTabContent(item)}</div>
    </div>
  `;
}

function detailTabButton(tab, label) {
  return `<button class="${state.objectDetailTab === tab ? "active" : ""}" onclick="setObjectDetailTab('${tab}')">${label}</button>`;
}

function objectTabContent(item) {
  if (state.objectDetailTab === "global") {
    return `
      <div class="detail">
        <div class="kv">
          <span>ID</span><strong class="mono">${item.id}</strong>
          <span>FMC ID</span><strong class="mono">${escapeHtml(item.fmc_id || t("localObject"))}</strong>
          <span>Domain</span><strong class="mono">${escapeHtml(item.domain_id)}</strong>
          <span>${t("state")}</span><strong>${sourcePill(item)}</strong>
          <span>${t("globalValue")}</span><strong class="mono">${escapeHtml(item.display_value || item.value)}</strong>
          <span>${t("overrideAllowed")}</span><strong>${item.overridable ? t("yes") : t("no")}</strong>
          <span>${t("lastSync")}</span><strong>${escapeHtml(item.last_seen_at || "-")}</strong>
          <span>${t("description")}</span><strong>${escapeHtml(item.description || "-")}</strong>
        </div>
        ${item.overridable ? "" : `<div class="error">${state.lang === "en" ? "This object does not have override enabled in FMC. Enable override in object edit and save it." : "Tento objekt nemá ve FMC povolený override. Zapněte 'Povolit override' v editaci objektu a uložte ho."}</div>`}
      </div>
    `;
  }
  if (state.objectDetailTab === "overrides") {
    return `
      <div class="panel-header">
        <div class="panel-title">Overrides</div>
      </div>
      <div id="overrides"></div>
    `;
  }
  if (state.objectDetailTab === "usage") {
    return `
      <div class="detail">
        <div class="empty">${state.lang === "en" ? "Usage references are not loaded from FMC API yet. The object is ready for adding a reference endpoint." : "Usage reference zatím nejsou načítané z FMC API. Objekt je připravený pro doplnění referenčního endpointu."}</div>
      </div>
    `;
  }
  return `
    <div class="panel-header"><div class="panel-title">History</div></div>
    <div id="object-history"></div>
  `;
}

function setObjectDetailTab(tab) {
  state.objectDetailTab = tab;
  renderObjects();
}

function renderObjectTab(item) {
  if (state.objectDetailTab === "overrides") renderObjectOverrides(item.id);
  if (state.objectDetailTab === "history") renderObjectHistory(item.id);
}

async function renderObjectOverrides(objectId) {
  const data = await api(`/api/objects/${objectId}/overrides`);
  const holder = document.getElementById("overrides");
  if (!holder) return;
  holder.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr><th>${t("targetFw")}</th><th>${t("targetId")}</th><th>${t("overrideValue")}</th><th>${t("description")}</th><th>Source</th><th>${t("lastSync")}</th><th>${t("action")}</th></tr></thead>
        <tbody>
          ${data.items.map((item) => `
            <tr>
              <td><strong>${escapeHtml(item.device_name)}</strong></td>
              <td class="mono">${escapeHtml(item.device_id || "-")}</td>
              <td class="mono">${escapeHtml(item.override_value)}</td>
              <td>${escapeHtml(item.description || "-")}</td>
              <td><span class="pill ${item.source === "fmc" ? "green" : "warn"}">${escapeHtml(item.source || "local")}</span></td>
              <td>${escapeHtml(item.last_seen_at || "-")}</td>
              <td class="actions">
                ${can("operator") ? `<button onclick="openOverrideModal(${objectId}, ${item.id})">${t("edit")}</button>` : ""}
                ${can("operator") ? `<button class="danger" onclick="deleteOverride(${item.id})">${t("deleteOverrideValue")}</button>` : ""}
              </td>
            </tr>
          `).join("") || `<tr><td colspan="7"><div class="empty">${t("noOverrides")}</div></td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

async function renderOverridableObjects() {
  const params = new URLSearchParams();
  if (state.overridableFilters.q) params.set("q", state.overridableFilters.q);
  if (state.overridableFilters.type) params.set("type", state.overridableFilters.type);
  const data = await api(`/api/overridable-objects?${params}`);
  const items = data.items || [];
  const topbar = document.querySelector("[data-topbar-actions]");
  topbar.innerHTML = can("operator") ? `
    <button data-action="sync" onclick="syncFmc()" ${state.busy.sync ? "disabled" : ""}>${state.busy.sync ? `<span class="spinner"></span>${t("syncing")}` : t("syncFmc")}</button>
  ` : "";
  document.getElementById("view").innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">${t("overridableObjects")}</div>
          <div class="muted">${t("originalVsOverrides")}</div>
        </div>
        <div class="toolbar">
          <input id="overridable-search" placeholder="${t("search")}" value="${escapeHtml(state.overridableFilters.q)}">
          <select id="overridable-type">
            ${objectTypeOptions(state.overridableFilters.type, true)}
          </select>
        </div>
      </div>
      <div class="override-matrix">
        ${items.map(overridableObjectCard).join("") || `<div class="empty">${t("noOverridableObjects")}</div>`}
      </div>
    </div>
  `;
  document.getElementById("overridable-search").addEventListener("input", debounce((event) => {
    state.overridableFilters.q = event.target.value;
    renderOverridableObjects();
  }, 250));
  document.getElementById("overridable-type").addEventListener("change", (event) => {
    state.overridableFilters.type = event.target.value;
    renderOverridableObjects();
  });
  renderDebugPanel();
}

function overridableObjectCard(item) {
  return `
    <section class="override-card">
      <div class="override-card-main">
        <div>
          <div class="object-name">${escapeHtml(item.name)}</div>
          <div class="muted">${escapeHtml(objectTypeLabel(item.object_type))} · ${sourceLabel(item).label}</div>
        </div>
        <span class="pill ${item.override_count ? "green" : ""}">${Number(item.override_count || 0)} ${t("overrideVariants")}</span>
      </div>
      <div class="override-table">
        <div class="override-table-head">
          <span>${t("targetFw")}</span>
          <span>${t("value")}</span>
          <span>${t("description")}</span>
          <span>Source</span>
        </div>
        <div class="override-table-row global-row">
          <div>
            <strong>${t("globalValue")}</strong>
            <div class="muted mono">${escapeHtml(item.fmc_id || item.domain_id || "-")}</div>
          </div>
          <strong class="mono">${escapeHtml(item.display_value || item.value || "-")}</strong>
          <strong>${escapeHtml(item.description || "-")}</strong>
          <strong>${sourcePill(item)}</strong>
        </div>
        ${(item.overrides || []).map((override) => `
          <div class="override-table-row">
            <div>
              <strong>${escapeHtml(override.device_name || "-")}</strong>
              <div class="muted mono">${escapeHtml(override.device_id || "-")}</div>
            </div>
            <strong class="mono">${escapeHtml(override.override_value || "-")}</strong>
            <strong>${escapeHtml(override.description || "-")}</strong>
            <strong><span class="pill ${override.source === "fmc" ? "green" : "warn"}">${escapeHtml(override.source || "local")}</span></strong>
          </div>
        `).join("") || `<div class="empty compact">${t("noOverrideVariants")}</div>`}
      </div>
    </section>
  `;
}

async function renderObjectHistory(objectId) {
  const data = await api("/api/audit");
  const holder = document.getElementById("object-history");
  if (!holder) return;
  const items = (data.items || []).filter((item) => item.target_type === "object" && String(item.target_id) === String(objectId));
  holder.innerHTML = auditTable(items);
}

async function refreshObjectFromFmc(id) {
  state.busy.refreshId = id;
  renderObjects();
  try {
    const result = await api(`/api/objects/${id}/refresh-fmc`, { method: "POST" });
    state.selectedObjectId = id;
    const imported = result?.overrides?.imported ?? 0;
    notify(`${t("refreshDone")} Override z FMC: ${imported}.`);
  } catch (error) {
    notify(error.message, "error");
  } finally {
    state.busy.refreshId = null;
    await renderObjects();
  }
}

function selectObject(id) {
  state.selectedObjectId = id;
  state.objectDetailTab = "global";
  renderObjects();
}

async function loadDevices() {
  if (state.cache.devices) return state.cache.devices;
  const data = await api("/api/fmc/devices");
  state.cache.devices = data.items || [];
  state.cache.devicesWarning = data.warning || "";
  return state.cache.devices;
}

async function openObjectModal(id = null) {
  const existing = id ? state.cache.objects.find((item) => item.id === id) : null;
  state.modalObject = existing || null;
  state.modalPortObjects = [];
  state.modalNetworkObjects = [];
  try {
    const [portData, hostData, networkData, rangeData, fqdnData] = await Promise.all([
      api("/api/objects?type=ProtocolPortObject&source=fmc"),
      api("/api/objects?type=Host&source=fmc"),
      api("/api/objects?type=Network&source=fmc"),
      api("/api/objects?type=Range&source=fmc"),
      api("/api/objects?type=FQDN&source=fmc"),
    ]);
    state.modalPortObjects = portData.items || [];
    state.modalNetworkObjects = [
      ...(hostData.items || []),
      ...(networkData.items || []),
      ...(rangeData.items || []),
      ...(fqdnData.items || []),
    ];
  } catch (error) {
    state.modalPortObjects = [];
    state.modalNetworkObjects = [];
  }
  const selectedType = existing?.object_type && PORT_OBJECT_TYPES.includes(existing.object_type) ? "ProtocolPortObject" : (existing?.object_type || "Host");
  const actualType = existing?.object_type || selectedType;
  openModal(`
    <form class="form-grid" onsubmit="saveObject(event, ${id || "null"})">
      <label>${t("type")}
        <select name="object_type" onchange="renderObjectFormFields(this.form)" ${id ? "disabled" : ""}>
          ${objectTypeOptions(selectedType, false)}
        </select>
      </label>
      ${id ? `<input type="hidden" name="object_type" value="${escapeHtml(actualType)}">` : ""}
      <div id="object-form-fields"></div>
      <div class="modal-footer" id="object-modal-footer">
        <button type="button" onclick="closeModal()">${t("close")}</button>
        <button class="primary" type="submit">${t("save")}</button>
      </div>
    </form>
  `, id ? t("edit") : t("newObject"));
  const form = document.querySelector("#modal form");
  if (form) renderObjectFormFields(form);
}

function splitPortValue(value = "", objectType = "ProtocolPortObject") {
  const text = String(value || "");
  if (objectType === "ICMPV4Object" || /^icmp\//i.test(text)) {
    const parts = text.replace(/^icmp\//i, "").split("/");
    return { protocol: "ICMP", icmpType: parts[0] || "any", icmpCode: parts[1] || "any", port: "" };
  }
  if (objectType === "ICMPV6Object" || /^ipv6-icmp\//i.test(text)) {
    const parts = text.replace(/^ipv6-icmp\//i, "").split("/");
    return { protocol: "IPv6-ICMP", icmpType: parts[0] || "any", icmpCode: parts[1] || "any", port: "" };
  }
  const other = text.match(/^protocol\s*\/\s*([^/]+)(?:\/(.+))?$/i);
  if (other) return { protocol: "Other", protocolNumber: other[1] || "", otherPort: other[2] || "any", port: other[2] || "any" };
  const match = text.match(/^(tcp|udp)\s*\/\s*(.+)$/i);
  if (!match) return { protocol: "TCP", port: value || "" };
  return { protocol: match[1].toUpperCase(), port: match[2], icmpType: "any", icmpCode: "any" };
}

function renderObjectFormFields(form) {
  const existing = state.modalObject || {};
  const selectedType = form.querySelector('select[name="object_type"]')?.value || form.querySelector('input[name="object_type"]')?.value || "Host";
  const type = existing.id ? existing.object_type : selectedType;
  const previousMode = form.querySelector('select[name="port_mode"]')?.value;
  const previousNetworkMode = form.querySelector('select[name="network_mode"]')?.value;
  const portMode = existing.object_type === "PortGroup" || type === "PortGroup" ? "group" : previousMode || "object";
  const networkMode = existing.object_type === "NetworkGroup" || type === "NetworkGroup" ? "group" : previousNetworkMode || "object";
  const holder = form.querySelector("#object-form-fields");
  const footer = form.querySelector("#object-modal-footer");
  if (!holder || !footer) return;

  if (isNetworkFamilyType(type) && !existing.id && networkMode === "import") {
    holder.innerHTML = networkImportFields();
    footer.innerHTML = `
      <button type="button" onclick="closeModal()">${t("close")}</button>
      <button class="primary" type="button" onclick="importCsvObjects('network')">${t("importCsv")}</button>
    `;
    return;
  }

  if (isPortObjectType(type) && !existing.id && portMode === "import") {
    holder.innerHTML = `
      <label>${t("action")}
        <select name="port_mode" onchange="renderObjectFormFields(this.form)">
          <option value="object">${t("addObject")}</option>
          <option value="import" selected>${t("importObject")}</option>
          <option value="group">${t("addGroup")}</option>
        </select>
      </label>
      <div class="import-help">
        <h3>${t("importPortObjects")}</h3>
        <p>${t("csvHeaderMandatory")}<br>${t("csvHeaderUppercase")}</p>
        <p>${state.lang === "en" ? "The header for Port object should have the below columns" : "Hlavička pro Port objekty musí obsahovat tyto sloupce"}<br><strong>NAME,PROTOCOL,PORT,ICMPCODE,ICMPTYPE</strong></p>
        <p>${t("sampleData")}<br>
          <span class="mono">port_1,UDP,10,,</span><br>
          <span class="mono">port_2,TCP,10-30,,</span><br>
          <span class="mono">port_3,ICMP,,any,any</span>
        </p>
      </div>
      <label>${t("importCsvFile")}
        <input name="csv_file" type="file" accept=".csv,text/csv">
      </label>
      <div class="muted">${state.lang === "en" ? "CSV rows are imported as Port objects and written to FMC when the connector is configured." : "Řádky z CSV se importují jako Port objekty a zapíšou do FMC, pokud je konektor nastavený."}</div>
    `;
    footer.innerHTML = `
      <button type="button" onclick="closeModal()">${t("close")}</button>
      <button class="primary" type="button" onclick="importCsvObjects('port')">${t("importCsv")}</button>
    `;
    return;
  }

  footer.innerHTML = `
    <button type="button" onclick="closeModal()">${t("close")}</button>
    <button class="primary" type="submit">${t("save")}</button>
  `;
  if (isNetworkFamilyType(type)) {
    holder.innerHTML = networkObjectFields(existing, !existing.id, networkMode, type);
    return;
  }
  if ((isPortObjectType(type) && portMode === "group") || type === "PortGroup") {
    holder.innerHTML = portGroupFields(existing, type === "ProtocolPortObject");
    return;
  }
  if (isPortObjectType(type)) {
    holder.innerHTML = portObjectFields(existing, !existing.id, portMode);
    updatePortProtocolFields(form);
    return;
  }
  holder.innerHTML = genericObjectFields(existing);
}

function commonObjectFields(existing) {
  return `
    <label>${t("description")}
      <textarea name="description">${escapeHtml(existing?.description || "")}</textarea>
    </label>
    <label class="switch"><input type="checkbox" name="overridable" ${existing?.overridable === false ? "" : "checked"}> ${t("overrideAllowed")}</label>
    <label class="switch"><input type="checkbox" name="sync_to_fmc" checked> ${state.lang === "en" ? "Write to FMC if connector is configured" : "Zapsat do FMC, pokud je konektor nastavený"}</label>
  `;
}

function genericObjectFields(existing) {
  return `
    <label>${t("name")}
      <input name="name" value="${escapeHtml(existing?.name || "")}" required>
    </label>
    <label>${t("value")}
      <input name="value" class="mono" value="${escapeHtml(existing?.value || "")}" required>
    </label>
    ${commonObjectFields(existing)}
  `;
}

function isNetworkFamilyType(type) {
  return ["Host", "Network", "Range", "FQDN", "NetworkGroup"].includes(type);
}

function isPortObjectType(type) {
  return PORT_OBJECT_TYPES.includes(type);
}

function networkImportFields() {
  return `
    <label>${t("action")}
      <select name="network_mode" onchange="renderObjectFormFields(this.form)">
        <option value="object">${t("addObject")}</option>
        <option value="import" selected>${t("importObject")}</option>
        <option value="group">${t("addGroup")}</option>
      </select>
    </label>
    <div class="import-help">
      <h3>${t("importNetworkObjects")}</h3>
      <p>${t("csvHeaderMandatory")}<br>${t("csvHeaderUppercase")}</p>
      <p>${state.lang === "en" ? "The header for Network object should have the below columns" : "Hlavička pro Network objekty musí obsahovat tyto sloupce"}<br><strong>NAME,DESCRIPTION,TYPE,VALUE,LOOKUP</strong></p>
      <p>${t("sampleData")}<br>
        <span class="mono">Object_1,inside edge host,Host,172.44.55.66,</span><br>
        <span class="mono">Object_2,dns host range,Range,2.2.2.3-2.2.2.9,</span><br>
        <span class="mono">Object_3,,FQDN,example.com,</span>
      </p>
    </div>
    <label>${t("importCsvFile")}
      <input name="csv_file" type="file" accept=".csv,text/csv">
    </label>
  `;
}

function networkObjectFields(existing, showMode, selectedMode, selectedType) {
  if ((selectedType === "NetworkGroup") || (showMode && selectedMode === "group")) {
    return networkGroupFields(existing, showMode);
  }
  const objectType = existing?.object_type && isNetworkFamilyType(existing.object_type) && existing.object_type !== "NetworkGroup"
    ? existing.object_type
    : (["Host", "Range", "Network", "FQDN"].includes(selectedType) ? selectedType : "Host");
  return `
    ${showMode ? `
      <label>${t("action")}
        <select name="network_mode" onchange="renderObjectFormFields(this.form)">
          <option value="object" ${selectedMode === "object" ? "selected" : ""}>${t("addObject")}</option>
          <option value="import" ${selectedMode === "import" ? "selected" : ""}>${t("importObject")}</option>
          <option value="group" ${selectedMode === "group" ? "selected" : ""}>${t("addGroup")}</option>
        </select>
      </label>
    ` : ""}
    <label>${t("name")}
      <input name="name" value="${escapeHtml(existing?.name || "")}" required>
    </label>
    <label>${t("description")}
      <textarea name="description">${escapeHtml(existing?.description || "")}</textarea>
    </label>
    <input type="hidden" name="network_subtype" value="${escapeHtml(objectType)}">
    <label>${t("value")}
      <input name="value" class="mono" value="${escapeHtml(existing?.value || "")}" placeholder="10.0.0.1, 10.0.0.0/24, 10.0.0.1-10.0.0.10 nebo example.com" required>
    </label>
    <label class="switch"><input type="checkbox" name="overridable" ${existing?.overridable === false ? "" : "checked"}> ${t("overrideAllowed")}</label>
    <label class="switch"><input type="checkbox" name="sync_to_fmc" checked> ${state.lang === "en" ? "Write to FMC if connector is configured" : "Zapsat do FMC, pokud je konektor nastavený"}</label>
  `;
}

function networkGroupFields(existing, showMode) {
  const existingMembers = existing?.network_group_members || [];
  const selected = new Set(existingMembers.map((item) => item.id));
  const objectMap = new Map();
  (state.modalNetworkObjects || []).filter((item) => item.fmc_id).forEach((item) => {
    objectMap.set(item.fmc_id, item);
  });
  existingMembers.forEach((item) => {
    if (item.id && !objectMap.has(item.id)) {
      objectMap.set(item.id, { fmc_id: item.id, name: item.name || item.id, object_type: item.type || "Host", value: "" });
    }
  });
  const objects = [...objectMap.values()].sort((a, b) => objectTypeLabel(a.object_type).localeCompare(objectTypeLabel(b.object_type), "cs-CZ") || a.name.localeCompare(b.name, "cs-CZ"));
  return `
    ${showMode ? `
      <label>${t("action")}
        <select name="network_mode" onchange="renderObjectFormFields(this.form)">
          <option value="object">${t("addObject")}</option>
          <option value="import">${t("importObject")}</option>
          <option value="group" selected>${t("addGroup")}</option>
        </select>
      </label>
    ` : ""}
    <label>${t("groupName")}
      <input name="name" value="${escapeHtml(existing?.name || "")}" required>
    </label>
    <label>${t("description")}
      <textarea name="description">${escapeHtml(existing?.description || "")}</textarea>
    </label>
    <div>
      <div class="field-label">${t("networkObjects")}</div>
      <div class="check-list">
        ${objects.map((item) => `
          <label class="check-row">
            <input type="checkbox" name="network_group_member" value="${escapeHtml(item.fmc_id)}" data-name="${escapeHtml(item.name)}" data-type="${escapeHtml(item.object_type)}" ${selected.has(item.fmc_id) ? "checked" : ""}>
            <span><strong>${escapeHtml(item.name)}</strong><span class="muted"> ${escapeHtml(item.display_value || item.value || "")}</span></span>
          </label>
        `).join("") || `<div class="empty">${state.lang === "en" ? "No Network objects are loaded from FMC. Use FMC sync first." : "Nejsou načtené žádné Network objekty z FMC. Nejdříve použijte Sync z FMC."}</div>`}
      </div>
    </div>
    <label class="switch"><input type="checkbox" name="overridable" ${existing?.overridable === false ? "" : "checked"}> ${t("overrideAllowed")}</label>
    <label class="switch"><input type="checkbox" name="sync_to_fmc" checked> ${state.lang === "en" ? "Write to FMC if connector is configured" : "Zapsat do FMC, pokud je konektor nastavený"}</label>
  `;
}

function portObjectFields(existing, showMode, selectedMode) {
  const port = splitPortValue(existing?.value || "", existing?.object_type || "ProtocolPortObject");
  return `
    ${showMode ? `
      <label>${t("action")}
        <select name="port_mode" onchange="renderObjectFormFields(this.form)">
          <option value="object" ${selectedMode === "object" ? "selected" : ""}>${t("addObject")}</option>
          <option value="import" ${selectedMode === "import" ? "selected" : ""}>${t("importObject")}</option>
          <option value="group" ${selectedMode === "group" ? "selected" : ""}>${t("addGroup")}</option>
        </select>
      </label>
    ` : ""}
    <label>${t("name")}
      <input name="name" value="${escapeHtml(existing?.name || "")}" required>
    </label>
    <label>Protocol
      <select name="port_protocol" onchange="updatePortProtocolFields(this.form)">
        ${selectOptions(["TCP", "UDP", "ICMP", "IPv6-ICMP", "Other"], port.protocol)}
      </select>
    </label>
    <label data-port-field="port">Port
      <input name="port_number" class="mono" value="${escapeHtml(port.port || "")}" placeholder="443 nebo 1024-65535">
    </label>
    <div data-port-field="icmp" class="field-pair">
      <label>Type
        <select name="icmp_type" onchange="updatePortProtocolFields(this.form)">
          ${icmpOptions(port.icmpType || "any")}
        </select>
      </label>
      <label>Code
        <select name="icmp_code">
          ${icmpCodeOptions(port.icmpCode || "any")}
        </select>
      </label>
    </div>
    <input type="hidden" name="icmp_code_value" value="${escapeHtml(port.icmpCode || "any")}">
    ${commonObjectFields(existing)}
  `;
}

function portOverrideValueFields(object, existing, originalValue) {
  const currentValue = existing?.override_value || originalValue || "";
  const port = splitPortValue(currentValue, object?.object_type || "ProtocolPortObject");
  return `
    <label>${t("originalValue")}
      <input class="mono" value="${escapeHtml(originalValue)}" disabled>
    </label>
    <label>Protocol
      <select name="port_protocol" onchange="updatePortProtocolFields(this.form)">
        ${selectOptions(["TCP", "UDP", "ICMP", "IPv6-ICMP", "Other"], port.protocol)}
      </select>
    </label>
    <label data-port-field="port">Port
      <input name="port_number" class="mono" value="${escapeHtml(port.port || "")}" placeholder="443 nebo 1024-65535">
    </label>
    <div data-port-field="icmp" class="field-pair">
      <label>Type
        <select name="icmp_type" onchange="updatePortProtocolFields(this.form)">
          ${icmpOptions(port.icmpType || "any")}
        </select>
      </label>
      <label>Code
        <select name="icmp_code">
          ${icmpCodeOptions(port.icmpCode || "any")}
        </select>
      </label>
    </div>
    <input type="hidden" name="icmp_code_value" value="${escapeHtml(port.icmpCode || "any")}">
  `;
}

function selectOptions(options, selected) {
  return options.map((option) => {
    const value = typeof option === "string" ? option : option.value;
    const label = typeof option === "string" ? option : option.label;
    return `<option value="${escapeHtml(value)}" ${String(selected).toLowerCase() === String(value).toLowerCase() ? "selected" : ""}>${escapeHtml(label)}</option>`;
  }).join("");
}

function icmpOptions(selected) {
  const options = [{ value: "any", label: "Any" }];
  for (let i = 0; i <= 255; i += 1) options.push(String(i));
  return selectOptions(options, selected);
}

function icmpCodeOptions(selected) {
  const options = [{ value: "any", label: "Any" }];
  for (let i = 0; i <= 255; i += 1) options.push(String(i));
  return selectOptions(options, selected);
}

function updateIcmpCodeState(form) {
  const typeSelect = form.querySelector('select[name="icmp_type"]');
  const codeSelect = form.querySelector('select[name="icmp_code"]');
  const storedCode = form.querySelector('input[name="icmp_code_value"]');
  if (!typeSelect || !codeSelect) return;
  if (typeSelect.value === "any") {
    if (storedCode) storedCode.value = codeSelect.value || "any";
    codeSelect.value = "any";
    codeSelect.disabled = true;
  } else {
    codeSelect.disabled = false;
    if (storedCode && storedCode.value && storedCode.value !== "any") codeSelect.value = storedCode.value;
  }
}

function updatePortProtocolFields(form) {
  const protocol = form.querySelector('select[name="port_protocol"]')?.value || form.querySelector('input[name="port_protocol"]')?.value || "TCP";
  form.querySelectorAll("[data-port-field]").forEach((node) => {
    const kind = node.dataset.portField;
    const visible =
      (kind === "port" && ["TCP", "UDP", "Other"].includes(protocol)) ||
      (kind === "icmp" && ["ICMP", "IPv6-ICMP"].includes(protocol));
    node.hidden = !visible;
    node.querySelectorAll("input, select").forEach((input) => {
      if (input.name === "icmp_code") return;
      input.required = visible && input.name !== "icmp_type";
    });
  });
  updateIcmpCodeState(form);
}

function portValueFromForm(form) {
  const protocol = form.querySelector('select[name="port_protocol"]')?.value || form.querySelector('input[name="port_protocol"]')?.value || "TCP";
  if (protocol === "ICMP") {
    return {
      object_type: "ICMPV4Object",
      value: `icmp/${(form.querySelector('[name="icmp_type"]')?.value || "any").trim()}/${(form.querySelector('[name="icmp_code"]')?.value || "any").trim()}`,
    };
  }
  if (protocol === "IPv6-ICMP") {
    return {
      object_type: "ICMPV6Object",
      value: `ipv6-icmp/${(form.querySelector('[name="icmp_type"]')?.value || "any").trim()}/${(form.querySelector('[name="icmp_code"]')?.value || "any").trim()}`,
    };
  }
  if (protocol === "Other") {
    return {
      object_type: "ProtocolPortObject",
      value: `protocol/all/${(form.querySelector('[name="port_number"]')?.value || "").trim()}`,
    };
  }
  return {
    object_type: "ProtocolPortObject",
    value: `${protocol.toLowerCase()}/${(form.querySelector('[name="port_number"]')?.value || "").trim()}`,
  };
}

function cleanupPortFormBody(body) {
  delete body.port_protocol;
  delete body.port_number;
  delete body.icmp_type;
  delete body.icmp_code;
  delete body.icmp_code_value;
  delete body.port_mode;
  delete body.port_group_member;
}

function portGroupFields(existing, showMode) {
  const existingMembers = existing?.port_group_members || [];
  const selected = new Set(existingMembers.map((item) => item.id));
  const portMap = new Map();
  (state.modalPortObjects || []).filter((item) => item.fmc_id).forEach((item) => {
    portMap.set(item.fmc_id, item);
  });
  existingMembers.forEach((item) => {
    if (item.id && !portMap.has(item.id)) {
      portMap.set(item.id, { fmc_id: item.id, name: item.name || item.id, value: "" });
    }
  });
  const ports = [...portMap.values()];
  return `
    ${showMode ? `
      <label>${t("action")}
        <select name="port_mode" onchange="renderObjectFormFields(this.form)">
          <option value="object">${t("addObject")}</option>
          <option value="import">${t("importObject")}</option>
          <option value="group" selected>${t("addGroup")}</option>
        </select>
      </label>
    ` : ""}
    <label>${t("groupName")}
      <input name="name" value="${escapeHtml(existing?.name || "")}" required>
    </label>
    <div>
      <div class="field-label">${t("portObjects")}</div>
      <div class="check-list">
        ${ports.map((item) => `
          <label class="check-row">
            <input type="checkbox" name="port_group_member" value="${escapeHtml(item.fmc_id)}" data-name="${escapeHtml(item.name)}" data-type="${escapeHtml(item.object_type || "ProtocolPortObject")}" ${selected.has(item.fmc_id) ? "checked" : ""}>
            <span><strong>${escapeHtml(item.name)}</strong><span class="muted"> ${escapeHtml(item.display_value || item.value || "")}</span></span>
          </label>
        `).join("") || `<div class="empty">${state.lang === "en" ? "No Port objects are loaded from FMC. Use FMC sync first." : "Nejsou načtené žádné Port objekty z FMC. Nejdříve použijte Sync z FMC."}</div>`}
      </div>
    </div>
    ${commonObjectFields(existing)}
  `;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];
    if (char === '"' && quoted && next === '"') {
      cell += '"';
      i += 1;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (char === "," && !quoted) {
      row.push(cell.trim());
      cell = "";
      continue;
    }
    if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && next === "\n") i += 1;
      row.push(cell.trim());
      if (row.some((value) => value !== "")) rows.push(row);
      row = [];
      cell = "";
      continue;
    }
    cell += char;
  }
  row.push(cell.trim());
  if (row.some((value) => value !== "")) rows.push(row);
  return rows;
}

function csvObjects(text, requiredHeaders) {
  const rows = parseCsv(text);
  if (!rows.length) throw new Error(state.lang === "en" ? "CSV file is empty." : "CSV soubor je prázdný.");
  const headers = rows[0].map((header) => header.trim());
  if (headers.some((header) => header !== header.toUpperCase())) throw new Error(t("csvHeaderUppercase"));
  const missing = requiredHeaders.filter((header) => !headers.includes(header));
  if (missing.length) throw new Error(`${t("csvHeaderMandatory")} ${missing.join(", ")}`);
  return rows.slice(1).map((row) => {
    const item = {};
    headers.forEach((header, index) => {
      item[header] = row[index] || "";
    });
    return item;
  }).filter((item) => Object.values(item).some((value) => value !== ""));
}

function csvNetworkType(value) {
  const normalized = String(value || "").trim().toLowerCase();
  const types = { host: "Host", range: "Range", network: "Network", fqdn: "FQDN" };
  return types[normalized] || "";
}

async function importCsvObjects(kind) {
  const form = document.querySelector("#modal form");
  const file = form?.querySelector('input[name="csv_file"]')?.files?.[0];
  if (!file) {
    modalError(state.lang === "en" ? "Choose a CSV file first." : "Nejprve vyberte CSV soubor.");
    return;
  }
  try {
    const text = await file.text();
    const rows = kind === "network"
      ? csvObjects(text, ["NAME", "DESCRIPTION", "TYPE", "VALUE", "LOOKUP"])
      : csvObjects(text, ["NAME", "PROTOCOL", "PORT", "ICMPCODE", "ICMPTYPE"]);
    let imported = 0;
    const errors = [];
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      try {
        let body;
        if (kind === "network") {
          const objectType = csvNetworkType(row.TYPE);
          if (!objectType) throw new Error(`TYPE ${row.TYPE || "-"}`);
          body = {
            object_type: objectType,
            name: row.NAME,
            description: row.DESCRIPTION || "",
            value: row.VALUE,
            overridable: true,
            sync_to_fmc: true,
          };
        } else {
          const protocol = String(row.PROTOCOL || "").trim().toUpperCase();
          let objectType = "ProtocolPortObject";
          let value = "";
          if (protocol === "TCP" || protocol === "UDP") {
            value = `${protocol.toLowerCase()}/${row.PORT}`;
          } else if (protocol === "ICMP") {
            objectType = "ICMPV4Object";
            value = `icmp/${row.ICMPTYPE || "any"}/${row.ICMPCODE || "any"}`;
          } else if (["ICMP6", "IPV6-ICMP", "IPV6ICMP"].includes(protocol)) {
            objectType = "ICMPV6Object";
            value = `ipv6-icmp/${row.ICMPTYPE || "any"}/${row.ICMPCODE || "any"}`;
          } else if (/^\d{1,5}$/.test(protocol)) {
            value = `protocol/${protocol}/${row.PORT || "any"}`;
          } else {
            throw new Error(`${protocol || "-"} ${state.lang === "en" ? "is not supported in this app import" : "není v importu aplikace podporován"}`);
          }
          body = {
            object_type: objectType,
            name: row.NAME,
            value,
            overridable: true,
            sync_to_fmc: true,
          };
        }
        await api("/api/objects", { method: "POST", body });
        imported += 1;
      } catch (error) {
        errors.push(`${index + 2}: ${error.message}`);
      }
    }
    if (imported) {
      closeModal();
      await renderObjects();
    }
    const message = `${t("csvImported")}: ${imported}${errors.length ? `, ${state.lang === "en" ? "errors" : "chyby"}: ${errors.slice(0, 3).join("; ")}` : ""}`;
    notify(message, errors.length ? "error" : "success");
  } catch (error) {
    modalError(error.message);
  }
}

function setBusyButtons(selector, busy, busyLabel, readyLabel) {
  document.querySelectorAll(selector).forEach((button) => {
    button.disabled = busy;
    button.innerHTML = busy ? `<span class="spinner"></span>${escapeHtml(busyLabel)}` : escapeHtml(readyLabel);
  });
}

async function saveObject(event, id) {
  event.preventDefault();
  const form = new FormData(event.target);
  const body = Object.fromEntries(form.entries());
  prepareObjectPayload(event.target, body);
  body.overridable = form.get("overridable") === "on";
  body.sync_to_fmc = form.get("sync_to_fmc") === "on";
  try {
    let result;
    if (id) {
      result = await api(`/api/objects/${id}`, { method: "PUT", body });
    } else {
      result = await api("/api/objects", { method: "POST", body });
      state.selectedObjectId = result.id;
    }
    closeModal();
    await renderObjects();
    notify(result?.fmc_write?.ok ? t("objectSavedFmc") : t("objectSavedLocal"));
  } catch (error) {
    modalError(error.message);
  }
}

function prepareObjectPayload(form, body) {
  if (isNetworkFamilyType(body.object_type) && body.network_mode === "group") {
    body.object_type = "NetworkGroup";
  }
  if (isNetworkFamilyType(body.object_type) && body.object_type !== "NetworkGroup") {
    body.object_type = body.network_subtype || body.object_type;
  }
  if (body.object_type === "NetworkGroup") {
    const members = [...form.querySelectorAll('input[name="network_group_member"]:checked')].map((input) => ({
      id: input.value,
      name: input.dataset.name || input.value,
      type: input.dataset.type || "Host",
    }));
    body.value = JSON.stringify(members);
  }
  if (body.object_type === "ProtocolPortObject" && body.port_mode === "group") {
    body.object_type = "PortGroup";
  }
  if (isPortObjectType(body.object_type)) {
    const portValue = portValueFromForm(form);
    body.object_type = portValue.object_type;
    body.value = portValue.value;
  }
  if (body.object_type === "PortGroup") {
    const members = [...form.querySelectorAll('input[name="port_group_member"]:checked')].map((input) => ({
      id: input.value,
      name: input.dataset.name || input.value,
      type: input.dataset.type || "ProtocolPortObject",
    }));
    body.value = JSON.stringify(members);
  }
  cleanupPortFormBody(body);
  delete body.network_mode;
  delete body.network_subtype;
  delete body.network_group_member;
}

async function deleteObject(id) {
  const object = (state.cache.objects || []).find((item) => item.id === id);
  const name = object?.name || `#${id}`;
  const target = object?.source === "missing_in_fmc"
    ? (state.lang === "en" ? "local cache record for an object missing in FMC" : "lokální záznam objektu, který ve FMC chybí")
    : (object?.fmc_id ? (state.lang === "en" ? "local cache and the FMC object" : "lokální cache i objekt ve FMC") : (state.lang === "en" ? "local object" : "lokální objekt"));
  if (!confirm(`${t("delete")} ${target} "${name}"? ${state.lang === "en" ? "This action also deletes local override records." : "Tato akce smaže i jeho lokální override záznamy."}`)) return;
  try {
    const result = await api(`/api/objects/${id}`, { method: "DELETE" });
    if (state.selectedObjectId === id) state.selectedObjectId = null;
    await renderObjects();
    notify(result?.fmc_write?.message || (result?.fmc_write?.ok ? (state.lang === "en" ? "Object deleted from FMC and local cache." : "Objekt smazán z FMC i lokální cache.") : (state.lang === "en" ? "Local object deleted." : "Lokální objekt smazán.")));
  } catch (error) {
    notify(error.message, "error");
  }
}

async function openOverrideModal(objectId, overrideId = null) {
  const object = (state.cache.objects || []).find((item) => item.id === objectId);
  if (object && !object.overridable) {
    notify(state.lang === "en" ? "Object does not have override enabled. Enable override in object edit first." : "Objekt nemá povolený override. Nejdříve zapněte 'Povolit override' v editaci objektu.", "error");
    return;
  }
  const [overrides, devices] = await Promise.all([
    api(`/api/objects/${objectId}/overrides`),
    loadDevices(),
  ]);
  const existing = overrides.items.find((item) => item.id === overrideId);
  const selectedDeviceId = existing?.device_id || "";
  const deviceOptions = devices.map((device) => {
    const label = `${device.name}${device.model ? ` · ${device.model}` : ""}`;
    return `<option value="${escapeHtml(device.id)}" data-name="${escapeHtml(device.name)}" data-type="${escapeHtml(device.type || "Device")}" ${selectedDeviceId === device.id ? "selected" : ""}>${escapeHtml(label)}</option>`;
  }).join("");
  const originalValue = object?.value || "";
  const overrideValueFields = object && isPortObjectType(object.object_type)
    ? portOverrideValueFields(object, existing, originalValue)
    : `
      <label>${t("originalValue")}
        <input class="mono" value="${escapeHtml(originalValue)}" disabled>
      </label>
      <label>Override hodnota
        <input name="override_value" class="mono" value="${escapeHtml(existing?.override_value || originalValue)}" data-original-value="${escapeHtml(originalValue)}" required>
      </label>
    `;
  openModal(`
    <form class="form-grid" onsubmit="saveOverride(event, ${objectId}, ${overrideId || "null"})">
      ${state.cache.devicesWarning ? `<div class="error">${escapeHtml(state.cache.devicesWarning)}</div>` : ""}
      <label>Target FW
        <select name="device_id" onchange="applySelectedDevice(this)" required>
          <option value="">Vyberte managed FW</option>
          ${deviceOptions}
        </select>
      </label>
      <input type="hidden" name="device_name" value="${escapeHtml(existing?.device_name || "")}">
      <input type="hidden" name="device_type" value="${escapeHtml(existing?.raw_fmc_payload?.overrides?.target?.type || existing?.raw_fmc_payload?.target?.type || "Device")}">
      <label>Target ID
        <input name="target_id_display" class="mono" value="${escapeHtml(existing?.device_id || "")}" disabled>
      </label>
      ${overrideValueFields}
      <label>Description
        <textarea name="description">${escapeHtml(existing?.description || "")}</textarea>
      </label>
      <div class="modal-footer">
        ${overrideId ? `<button class="danger" type="button" onclick="deleteOverrideFromModal(${overrideId})">${t("deleteOverrideValue")}</button>` : ""}
        <button type="button" onclick="closeModal()">${t("close")}</button>
        <button class="primary" type="submit">${t("save")}</button>
      </div>
    </form>
  `, overrideId ? `${t("edit")} override` : `${t("newObject")} override`);
  const select = document.querySelector('#modal select[name="device_id"]');
  if (select) applySelectedDevice(select, Boolean(existing?.override_value));
  const form = document.querySelector("#modal form");
  if (form) updatePortProtocolFields(form);
}

async function saveOverride(event, objectId, overrideId) {
  event.preventDefault();
  const form = event.target;
  const body = Object.fromEntries(new FormData(form).entries());
  if (form.querySelector('select[name="port_protocol"]')) {
    const portValue = portValueFromForm(form);
    body.override_value = portValue.value;
    body.override_object_type = portValue.object_type;
    cleanupPortFormBody(body);
  }
  try {
    let result;
    if (overrideId) {
      result = await api(`/api/overrides/${overrideId}`, { method: "PUT", body });
    } else {
      result = await api(`/api/objects/${objectId}/overrides`, { method: "POST", body });
    }
    closeModal();
    await renderObjects();
    notify(result?.fmc_write?.message || (result?.fmc_write?.ok ? t("overrideSavedFmc") : t("overrideSavedLocal")));
  } catch (error) {
    modalError(error.message);
  }
}

function applySelectedDevice(select, keepExistingValue = false) {
  const form = select.closest("form");
  const option = select.options[select.selectedIndex];
  const deviceName = option?.dataset?.name || "";
  const deviceId = select.value || "";
  const nameInput = form.querySelector('input[name="device_name"]');
  const typeInput = form.querySelector('input[name="device_type"]');
  const idDisplay = form.querySelector('input[name="target_id_display"]');
  const valueInput = form.querySelector('input[name="override_value"]');
  if (nameInput) nameInput.value = deviceName;
  if (typeInput) typeInput.value = option?.dataset?.type || "Device";
  if (idDisplay) idDisplay.value = deviceId;
  if (valueInput && !keepExistingValue && !valueInput.value) {
    valueInput.value = valueInput.dataset.originalValue || "";
  }
}

async function deleteOverride(id) {
  if (!confirm(t("confirmDeleteOverrideValue"))) return;
  const result = await api(`/api/overrides/${id}`, { method: "DELETE" });
  await renderObjects();
  notify(result?.fmc_write?.message || (result?.fmc_write?.ok ? t("overrideDeletedFmc") : t("overrideDeleted")));
}

async function deleteOverrideFromModal(id) {
  if (!confirm(t("confirmDeleteOverrideValue"))) return;
  const result = await api(`/api/overrides/${id}`, { method: "DELETE" });
  closeModal();
  await renderObjects();
  notify(result?.fmc_write?.message || (result?.fmc_write?.ok ? t("overrideDeletedFmc") : t("overrideDeleted")));
}

async function renderUsers() {
  if (!can("admin")) return setView("dashboard");
  const data = await api("/api/users");
  state.cache.users = data.items;
  document.querySelector("[data-topbar-actions]").innerHTML = `<button class="primary" onclick="openUserModal()">${state.lang === "en" ? "New user" : "Nový uživatel"}</button>`;
  document.getElementById("view").innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">${state.lang === "en" ? "Local users" : "Lokální uživatelé"}</div></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>${t("user")}</th><th>Role</th><th>${t("state")}</th><th>${state.lang === "en" ? "Last login" : "Poslední login"}</th><th>${t("action")}</th></tr></thead>
          <tbody>
            ${data.items.map((user) => `
              <tr>
                <td><strong>${escapeHtml(user.display_name)}</strong><div class="muted">${escapeHtml(user.username)}</div></td>
                <td><span class="pill blue">${escapeHtml(user.role)}</span></td>
                <td>${user.active ? `<span class="pill green">${state.lang === "en" ? "active" : "aktivní"}</span>` : `<span class="pill red">${state.lang === "en" ? "inactive" : "neaktivní"}</span>`}${user.force_password_change ? ` <span class="pill warn">${state.lang === "en" ? "password change" : "změna hesla"}</span>` : ""}</td>
                <td>${escapeHtml(user.last_login_at || "-")}</td>
                <td class="actions"><button onclick="openUserModalById(${user.id})">${t("edit")}</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function openUserModalById(id) {
  const user = (state.cache.users || []).find((item) => item.id === id);
  openUserModal(user || null);
}

function openUserModal(user = null) {
  openModal(`
    <form class="form-grid" onsubmit="saveUser(event, ${user ? user.id : "null"})">
      <label>${t("username")}
        <input name="username" value="${escapeHtml(user?.username || "")}" ${user ? "disabled" : "required"}>
      </label>
      <label>${state.lang === "en" ? "Display name" : "Zobrazované jméno"}
        <input name="display_name" value="${escapeHtml(user?.display_name || "")}" required>
      </label>
      <label>Role
        <select name="role">${Object.keys(roleLevel).map((role) => `<option value="${role}" ${user?.role === role ? "selected" : ""}>${role}</option>`).join("")}</select>
      </label>
      <label>${t("password")}
        <input name="password" type="password" ${user ? "" : "required"}>
      </label>
      ${user ? `<label class="switch"><input type="checkbox" name="active" ${user.active ? "checked" : ""}> ${state.lang === "en" ? "Active account" : "Aktivní účet"}</label>` : ""}
      <div class="modal-footer">
        <button type="button" onclick="closeModal()">${t("close")}</button>
        <button class="primary" type="submit">${t("save")}</button>
      </div>
    </form>
  `, user ? `${t("edit")} ${t("user").toLowerCase()}` : (state.lang === "en" ? "New user" : "Nový uživatel"));
}

async function saveUser(event, id) {
  event.preventDefault();
  const form = new FormData(event.target);
  const body = Object.fromEntries(form.entries());
  body.active = form.get("active") === "on" || !id;
  if (!body.password) delete body.password;
  try {
    if (id) {
      await api(`/api/users/${id}`, { method: "PATCH", body });
    } else {
      await api("/api/users", { method: "POST", body });
    }
    closeModal();
    await renderUsers();
    notify(state.lang === "en" ? "User saved." : "Uživatel uložen.");
  } catch (error) {
    modalError(error.message);
  }
}

async function renderSettings() {
  if (!can("admin")) return setView("dashboard");
  const settings = await api("/api/settings/fmc");
  document.getElementById("view").innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">${t("fmcConnector")}</div></div>
      <div class="detail">
        <form class="form-grid" onsubmit="saveSettings(event)">
          <label>Base URL
            <input name="base_url" value="${escapeHtml(settings.base_url)}" required>
          </label>
          <label>Service account
            <input name="username" value="${escapeHtml(settings.username)}">
          </label>
          <label>${state.lang === "en" ? "Service account password" : "Heslo service accountu"}
            <input name="password" type="password" placeholder="${settings.has_password ? (state.lang === "en" ? "saved" : "uloženo") : ""}">
          </label>
          <label>Domain UUID
            <input name="domain_uuid" class="mono" value="${escapeHtml(settings.domain_uuid)}">
          </label>
          <label class="switch"><input type="checkbox" name="verify_tls" ${settings.verify_tls ? "checked" : ""}> ${state.lang === "en" ? "Verify TLS certificate" : "Ověřovat TLS certifikát"}</label>
          <div class="muted">${state.lang === "en" ? "If FMC uses a self-signed certificate, disable this for lab use. In production, prefer importing the FMC CA certificate." : "Pokud FMC používá self-signed certifikát, pro lab provoz tuto volbu vypněte. Produkčně je lepší importovat CA certifikát FMC."}</div>
          <div class="actions">
            <button class="primary" type="submit">${t("save")}</button>
            <button type="button" onclick="testFmc()">${state.lang === "en" ? "Test connection" : "Test spojení"}</button>
            <button type="button" data-action="sync" onclick="syncFmc()" ${state.busy.sync ? "disabled" : ""}>${state.busy.sync ? `<span class="spinner"></span>${t("syncing")}` : t("syncFmc")}</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

async function saveSettings(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const body = Object.fromEntries(form.entries());
  body.verify_tls = form.get("verify_tls") === "on";
  if (!body.password) delete body.password;
  try {
    await api("/api/settings/fmc", { method: "PUT", body });
    notify(state.lang === "en" ? "FMC settings saved." : "FMC nastavení uloženo.");
    renderSettings();
  } catch (error) {
    notify(error.message, "error");
  }
}

async function testFmc() {
  try {
    const result = await api("/api/settings/fmc/test", { method: "POST" });
    notify(`${state.lang === "en" ? "FMC connection OK" : "FMC spojení OK"}, latency ${result.latency_ms} ms.`);
  } catch (error) {
    notify(error.message, "error");
  }
}

async function syncFmc(objectType = "all") {
  state.busy.sync = true;
  setBusyButtons("[data-action='sync']", true, t("syncing"), t("syncFmc"));
  try {
    const syncTypes = objectType === "network-family" ? ["Host", "Network", "Range", "FQDN", "NetworkGroup"] : [objectType];
    let result = { imported: 0, missing_in_fmc: 0, local_only: 0, local_modified: 0 };
    for (const syncType of syncTypes) {
      const partial = await api("/api/settings/fmc/sync", { method: "POST", body: { object_type: syncType, include_overrides: true } });
      result.imported += partial.imported || 0;
      result.missing_in_fmc += partial.missing_in_fmc || 0;
      result.local_only = partial.local_only || result.local_only;
      result.local_modified = partial.local_modified || result.local_modified;
    }
    if (state.view === "objects") await renderObjects();
    if (state.view === "overridable") await renderOverridableObjects();
    const label = objectType === "all" ? (state.lang === "en" ? "FMC objects" : "FMC objekty") : (objectType === "network-family" ? "Network objekty" : objectTypeLabel(objectType));
    const localCount = result.local_only + result.local_modified;
    notify(state.lang === "en"
      ? `${t("syncDone")}: ${label} ${result.imported}, missing in FMC ${result.missing_in_fmc}, local/not pushed ${localCount}.`
      : `${t("syncDone")}: ${label} ${result.imported}, nenalezeno ve FMC ${result.missing_in_fmc}, lokální/nepropsané ${localCount}.`);
  } catch (error) {
    notify(error.message, "error");
  } finally {
    state.busy.sync = false;
    setBusyButtons("[data-action='sync']", false, t("syncing"), t("syncFmc"));
  }
}

async function renderChanges() {
  const data = await api("/api/change-requests");
  document.getElementById("view").innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">Change requests</div></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Status</th><th>Cíl</th><th>Operace</th><th>Zadal</th><th>Čas</th><th>Akce</th></tr></thead>
          <tbody>
            ${data.items.map((item) => `
              <tr>
                <td class="mono">${item.id}</td>
                <td><span class="pill ${item.status === "pending" ? "warn" : "green"}">${escapeHtml(item.status)}</span></td>
                <td>${escapeHtml(item.target_type)} #${escapeHtml(item.target_id || "-")}</td>
                <td>${escapeHtml(item.operation)}</td>
                <td>${escapeHtml(item.requested_by_username)}</td>
                <td>${escapeHtml(item.created_at)}</td>
                <td>${can("approver") && item.status === "pending" ? `<button onclick="applyChange(${item.id})">Aplikovat</button>` : ""}</td>
              </tr>
            `).join("") || `<tr><td colspan="7"><div class="empty">Bez change requestů</div></td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function applyChange(id) {
  await api(`/api/change-requests/${id}/apply`, { method: "POST" });
  await renderChanges();
  notify("Change request aplikovan.");
}

async function renderAudit() {
  const data = await api("/api/audit");
  document.getElementById("view").innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">Audit log</div></div>
      ${auditTable(data.items)}
    </div>
  `;
}

function auditTable(items) {
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Čas</th><th>Uživatel</th><th>Akce</th><th>Cíl</th><th>IP</th></tr></thead>
        <tbody>
          ${items.map((item) => `
            <tr>
              <td>${escapeHtml(item.created_at)}</td>
              <td>${escapeHtml(item.username || "-")}</td>
              <td><span class="pill">${escapeHtml(item.action)}</span></td>
              <td>${escapeHtml(item.target_type || "-")} ${escapeHtml(item.target_id || "")}</td>
              <td class="mono">${escapeHtml(item.ip_address || "-")}</td>
            </tr>
          `).join("") || `<tr><td colspan="5"><div class="empty">Žádný audit</div></td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function openPasswordModal(forced = false) {
  openModal(`
    <form class="form-grid" onsubmit="changePassword(event)">
      ${forced ? `<div class="error">První přihlášení vyžaduje změnu hesla.</div>` : ""}
      <label>Aktuální heslo
        <input name="current_password" type="password" required>
      </label>
      <label>Nové heslo
        <input name="new_password" type="password" minlength="14" required>
      </label>
      <div class="modal-footer">
        ${forced ? "" : `<button type="button" onclick="closeModal()">Zavřít</button>`}
        <button class="primary" type="submit">Změnit heslo</button>
      </div>
    </form>
  `, "Změna hesla", forced);
}

async function changePassword(event) {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.target).entries());
  try {
    await api("/api/auth/change-password", { method: "POST", body });
    state.user.force_password_change = false;
    closeModal();
    notify("Heslo změněno.");
  } catch (error) {
    modalError(error.message);
  }
}

function openModal(body, title, locked = false) {
  closeModal();
  const node = document.createElement("div");
  node.className = "modal-backdrop";
  node.id = "modal";
  node.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <div class="panel-title">${escapeHtml(title)}</div>
        ${locked ? "" : `<button onclick="closeModal()">Zavřít</button>`}
      </div>
      <div class="modal-body">
        <div data-modal-error></div>
        ${body}
      </div>
    </div>
  `;
  document.body.appendChild(node);
}

function closeModal() {
  document.getElementById("modal")?.remove();
}

function modalError(message) {
  const holder = document.querySelector("[data-modal-error]");
  if (holder) holder.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
}

function debounce(fn, wait) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), wait);
  };
}

window.login = login;
window.logout = logout;
window.setLanguage = setLanguage;
window.toggleDebug = toggleDebug;
window.clearDebugLogs = clearDebugLogs;
window.setDebugFilter = setDebugFilter;
window.useSelectedDebugObject = useSelectedDebugObject;
window.toggleDebugOnlyMatches = toggleDebugOnlyMatches;
window.openPasswordModal = openPasswordModal;
window.changePassword = changePassword;
window.openObjectModal = openObjectModal;
window.renderObjectFormFields = renderObjectFormFields;
window.updatePortProtocolFields = updatePortProtocolFields;
window.importCsvObjects = importCsvObjects;
window.saveObject = saveObject;
window.deleteObject = deleteObject;
window.refreshObjectFromFmc = refreshObjectFromFmc;
window.selectObject = selectObject;
window.setObjectSort = setObjectSort;
window.setObjectDetailTab = setObjectDetailTab;
window.openOverrideModal = openOverrideModal;
window.saveOverride = saveOverride;
window.applySelectedDevice = applySelectedDevice;
window.deleteOverride = deleteOverride;
window.deleteOverrideFromModal = deleteOverrideFromModal;
window.openUserModal = openUserModal;
window.openUserModalById = openUserModalById;
window.saveUser = saveUser;
window.saveSettings = saveSettings;
window.testFmc = testFmc;
window.syncFmc = syncFmc;
window.applyChange = applyChange;
window.closeModal = closeModal;

init().catch((error) => {
  console.error(error);
  renderLogin(error.message);
});
