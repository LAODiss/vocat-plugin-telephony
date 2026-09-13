/* Panel for the vocat telephony assistant plugin.
 *
 * Two things shape this file.
 *
 * 1. vocat embeds plugin panels with
 *    sandbox="allow-scripts allow-forms allow-same-origin". That list omits
 *    allow-modals, so window.confirm/alert return immediately without showing
 *    anything. Confirmation is therefore inline.
 *
 * 2. The plugin backend receives no credentials — vocat's reverse proxy strips
 *    the session cookie and CSRF token. So when server-side mode is off, this
 *    page is the only thing that can act on a call, and it does so with the
 *    operator's own session against vocat's public API.
 */
"use strict";

var BACKEND = "/api/extensions/telephony-assistant/backend";
/* Panel-mode polling. One second is fast enough to reject or answer before a
 * typical caller gives up, and the endpoint reads in-memory state. */
var POLL_MS = 1000;

function el(id) { return document.getElementById(id); }

function esc(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function cookie(name) {
  var parts = document.cookie ? document.cookie.split("; ") : [];
  for (var i = 0; i < parts.length; i++) {
    var index = parts[i].indexOf("=");
    if (index > 0 && parts[i].slice(0, index) === name) {
      return decodeURIComponent(parts[i].slice(index + 1));
    }
  }
  return "";
}

/* vocat's session cookie is HttpOnly and rides along automatically on a
 * same-origin request; the CSRF cookie is readable so it can be echoed. */
function request(path, options) {
  options = options || {};
  var headers = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  var method = options.method || "GET";
  if (method !== "GET" && method !== "HEAD") {
    var token = cookie("vocat_csrf");
    if (token) headers["X-CSRF-Token"] = token;
  }
  return fetch(path, {
    method: method, headers: headers, credentials: "include",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  }).then(function (response) {
    var type = response.headers.get("content-type") || "";
    var parsed = type.indexOf("application/json") >= 0
      ? response.json()
      : response.text().then(function (text) { return { message: text }; });
    return parsed.then(function (payload) {
      if (!response.ok) {
        var detail = (payload && payload.error) || payload || {};
        var message = detail.message || detail.code || ("HTTP " + response.status);
        if (response.status === 401) message = "会话已过期，请重新登录 vocat。";
        throw new Error(message);
      }
      return payload && Object.prototype.hasOwnProperty.call(payload, "data")
        ? payload.data : payload;
    });
  });
}

function notice(target, kind, html) {
  el(target).innerHTML = html ? '<div class="notice ' + kind + '">' + html + "</div>" : "";
}

/* ---- state ---- */
var state = {
  rules: [], fallback: "allow", contacts: [], voicemail: {}, recording: {},
  notify: { templates: [] }, keepalive: [], credentials: {}, sip: {},
  engine: {}, devices: [], events: [], messages: [],
  defaults: [], eventNames: [],
  history: [], stats: {}, liveCalls: [],
  historyFilter: { direction: "", missed: false, recorded: false },
  pendingDelayed: [],
};

/* ---- tabs ---- */
var TABS = {
  dialer: "paneDialer", history: "paneHistory",
  rules: "paneRules", contacts: "paneContacts", voicemail: "paneVoicemail",
  notify: "paneNotify", keepalive: "paneKeepalive", events: "paneEvents",
  sip: "paneSIP", settings: "paneSettings",
};
var TAB_BUTTONS = {
  dialer: "tabDialer", history: "tabHistory",
  rules: "tabRules", contacts: "tabContacts", voicemail: "tabVoicemail",
  notify: "tabNotify", keepalive: "tabKeepalive", events: "tabEvents",
  sip: "tabSIP", settings: "tabSettings",
};

function showTab(which) {
  for (var key in TABS) {
    el(TABS[key]).className = key === which ? "" : "hidden";
    el(TAB_BUTTONS[key]).className = key === which ? "active" : "";
  }
  if (which === "events") loadEvents();
  if (which === "voicemail") loadMessages();
  if (which === "history") loadHistory();
  if (which === "dialer") loadLiveCalls();
  if (which === "sip") loadSIPStatus();
}

for (var key in TAB_BUTTONS) {
  (function (name) {
    el(TAB_BUTTONS[name]).addEventListener("click", function () { showTab(name); });
  })(key);
}

/* ---- engine banner ---- */
function renderBanner() {
  var engine = state.engine || {};
  var parts = [];
  if (engine.needs_credentials) {
    parts.push('<div class="notice warn">规则里有拒接/接听/留言动作，但服务端模式没开：' +
      "这些动作只在本页面打开时执行。到「设置」里开启服务端模式可让它 7×24 生效。</div>");
  } else if (!engine.enabled) {
    parts.push('<div class="notice info">面板模式：规则由当前页面执行，关闭页面即失效。</div>');
  } else if (engine.error) {
    parts.push('<div class="notice err">服务端模式未运行：' + esc(engine.error) + "</div>");
  } else if (engine.session_valid) {
    parts.push('<div class="notice ok">服务端模式已连接 vocat，规则在后台持续生效。</div>');
  } else {
    parts.push('<div class="notice warn">服务端模式已开启，但尚未登录成功。</div>');
  }
  el("engineBanner").innerHTML = parts.join("");
}

/* ---- rules ---- */
var MATCHES = [
  ["any", "全部来电"], ["number", "指定号码"], ["prefix", "号码前缀"],
  ["contact", "联系人簿内"], ["unknown", "陌生号码"], ["anonymous", "匿名/隐藏号码"],
];
var ACTIONS = [
  ["allow", "放行"], ["reject", "拒接"], ["answer", "接听"], ["voicemail", "转语音留言"],
];

function options(list, selected) {
  return list.map(function (pair) {
    return '<option value="' + pair[0] + '"' +
      (pair[0] === selected ? " selected" : "") + ">" + esc(pair[1]) + "</option>";
  }).join("");
}

function deviceOptions(selected, anyLabel) {
  var html = '<option value=""' + (!selected ? " selected" : "") + ">" + esc(anyLabel) + "</option>";
  html += (state.devices || []).map(function (device) {
    return '<option value="' + esc(device.id) + '"' +
      (device.id === selected ? " selected" : "") + ">" +
      esc(device.name || device.id) + "</option>";
  }).join("");
  return html;
}

function renderRules() {
  if (!state.rules.length) {
    el("ruleList").innerHTML = '<div class="empty">还没有规则。所有来电都按下面的默认动作处理。</div>';
    return;
  }
  var rows = state.rules.map(function (rule, index) {
    var needsValue = rule.match === "number" || rule.match === "prefix";
    return "<tr>" +
      '<td class="nowrap">' + (index + 1) +
        ' <button class="act small" data-act="up" data-i="' + index + '" title="上移">↑</button>' +
        ' <button class="act small" data-act="down" data-i="' + index + '" title="下移">↓</button></td>' +
      '<td><input type="checkbox" data-act="enabled" data-i="' + index + '"' +
        (rule.enabled ? " checked" : "") + " /></td>" +
      '<td><select data-act="match" data-i="' + index + '">' + options(MATCHES, rule.match) + "</select></td>" +
      '<td><input type="text" data-act="value" data-i="' + index + '" value="' + esc(rule.value || "") +
        '" placeholder="' + (needsValue ? "号码或前缀" : "不需要") + '"' +
        (needsValue ? "" : " disabled") + " /></td>" +
      '<td><select data-act="action" data-i="' + index + '">' + options(ACTIONS, rule.action) + "</select></td>" +
      '<td><select data-act="device" data-i="' + index + '">' + deviceOptions(rule.device_id, "全部设备") + "</select></td>" +
      '<td><input type="number" min="0" max="120" data-act="delay" data-i="' + index + '" value="' +
        (rule.delay_seconds || 0) + '" style="width:70px" /></td>' +
      '<td class="nowrap"><button class="act small danger" data-act="del" data-i="' + index + '">删除</button></td>' +
      "</tr>";
  }).join("");
  el("ruleList").innerHTML = "<table><thead><tr>" +
    "<th>顺序</th><th>启用</th><th>匹配</th><th>值</th><th>动作</th><th>设备</th><th>延迟(秒)</th><th></th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>";
  bindRuleEvents();
}

function bindRuleEvents() {
  var nodes = el("ruleList").querySelectorAll("[data-act]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("change", handleRuleChange);
    if (nodes[i].tagName === "BUTTON") {
      nodes[i].addEventListener("click", handleRuleChange);
    }
  }
}

function handleRuleChange(event) {
  var node = event.currentTarget;
  var index = Number(node.getAttribute("data-i"));
  var action = node.getAttribute("data-act");
  var rule = state.rules[index];
  if (!rule) return;
  switch (action) {
    case "enabled": rule.enabled = node.checked; return;
    case "match":
      rule.match = node.value;
      // A match kind that takes no value must not keep a stale one, or the
      // server will reject the save.
      if (rule.match !== "number" && rule.match !== "prefix") rule.value = "";
      renderRules();
      return;
    case "value": rule.value = node.value; return;
    case "action": rule.action = node.value; return;
    case "device": rule.device_id = node.value; return;
    case "delay": rule.delay_seconds = Number(node.value) || 0; return;
    case "del": state.rules.splice(index, 1); renderRules(); return;
    case "up":
      if (index > 0) {
        var previous = state.rules[index - 1];
        state.rules[index - 1] = rule;
        state.rules[index] = previous;
        renderRules();
      }
      return;
    case "down":
      if (index < state.rules.length - 1) {
        var next = state.rules[index + 1];
        state.rules[index + 1] = rule;
        state.rules[index] = next;
        renderRules();
      }
      return;
  }
}

el("addRule").addEventListener("click", function () {
  state.rules.push({ id: "", enabled: true, match: "any", value: "", action: "allow", device_id: "", delay_seconds: 0 });
  renderRules();
});

el("saveRules").addEventListener("click", function () {
  notice("ruleNotice", "", "");
  el("saveRules").disabled = true;
  request(BACKEND + "/rules", {
    method: "PUT", body: { rules: state.rules, fallback: el("fallback").value },
  }).then(function (data) {
    state.rules = data.rules || [];
    state.fallback = data.fallback;
    state.engine = data.engine || state.engine;
    renderRules();
    renderBanner();
    notice("ruleNotice", "ok", "规则已保存。");
  }).catch(function (error) {
    notice("ruleNotice", "err", esc(error.message));
  }).then(function () { el("saveRules").disabled = false; });
});

el("doEvaluate").addEventListener("click", function () {
  var number = el("testNumber").value.trim();
  if (!number) { notice("evaluateOut", "err", "请填写号码。"); return; }
  request(BACKEND + "/rules/evaluate", {
    method: "POST", body: { device_id: el("testDevice").value, number: number },
  }).then(function (data) {
    var label = {};
    ACTIONS.forEach(function (pair) { label[pair[0]] = pair[1]; });
    var detail = [];
    detail.push("动作：<strong>" + esc(label[data.action] || data.action) + "</strong>");
    detail.push(data.rule_id ? "命中规则 " + esc(data.rule_id) : "无规则命中，使用默认动作");
    if (data.contact_name) detail.push("联系人：" + esc(data.contact_name));
    if (data.anonymous) detail.push("识别为匿名号码");
    if (data.delay_seconds) detail.push("延迟 " + data.delay_seconds + " 秒后执行");
    notice("evaluateOut", data.action === "allow" ? "info" : "ok", detail.join("　·　"));
  }).catch(function (error) {
    notice("evaluateOut", "err", esc(error.message));
  });
});

/* ---- contacts ---- */
function renderContacts() {
  if (!state.contacts.length) {
    el("contactList").innerHTML = '<div class="empty">还没有联系人。</div>';
    return;
  }
  var rows = state.contacts.map(function (contact, index) {
    return "<tr>" +
      '<td><input type="text" data-act="name" data-i="' + index + '" value="' + esc(contact.name || "") + '" /></td>' +
      '<td><input type="text" data-act="number" data-i="' + index + '" value="' + esc(contact.number || "") + '" /></td>' +
      '<td><input type="text" data-act="note" data-i="' + index + '" value="' + esc(contact.note || "") + '" /></td>' +
      '<td class="nowrap"><button class="act small danger" data-act="del" data-i="' + index + '">删除</button></td>' +
      "</tr>";
  }).join("");
  el("contactList").innerHTML = "<table><thead><tr>" +
    "<th>姓名</th><th>号码</th><th>备注</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>";

  var nodes = el("contactList").querySelectorAll("[data-act]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("change", handleContactChange);
    if (nodes[i].tagName === "BUTTON") nodes[i].addEventListener("click", handleContactChange);
  }
}

function handleContactChange(event) {
  var node = event.currentTarget;
  var index = Number(node.getAttribute("data-i"));
  var action = node.getAttribute("data-act");
  var contact = state.contacts[index];
  if (!contact) return;
  if (action === "del") { state.contacts.splice(index, 1); renderContacts(); return; }
  contact[action] = node.value;
}

el("addContact").addEventListener("click", function () {
  state.contacts.push({ number: "", name: "", note: "" });
  renderContacts();
});

el("saveContacts").addEventListener("click", function () {
  notice("contactNotice", "", "");
  el("saveContacts").disabled = true;
  request(BACKEND + "/contacts", { method: "PUT", body: { contacts: state.contacts } })
    .then(function (data) {
      state.contacts = data.contacts || [];
      renderContacts();
      notice("contactNotice", "ok", "联系人已保存。");
    }).catch(function (error) {
      notice("contactNotice", "err", esc(error.message));
    }).then(function () { el("saveContacts").disabled = false; });
});

/* ---- voicemail ---- */
function renderVoicemail() {
  var settings = state.voicemail || {};
  el("vmEnabled").checked = !!settings.enabled;
  el("vmMax").value = settings.max_seconds || 60;
  el("vmSilence").value = settings.silence_seconds || 8;
  el("vmRetention").value = settings.retention_days || 0;
  el("vmQuota").value = Math.round((settings.max_total_bytes || 134217728) / 1048576);
  el("vmGreeting").value = settings.greeting_path || "";
}

el("saveVoicemail").addEventListener("click", function () {
  notice("vmNotice", "", "");
  el("saveVoicemail").disabled = true;
  request(BACKEND + "/voicemail/settings", {
    method: "PUT",
    body: {
      enabled: el("vmEnabled").checked,
      greeting_path: el("vmGreeting").value.trim(),
      max_seconds: Number(el("vmMax").value) || 60,
      silence_seconds: Number(el("vmSilence").value) || 8,
      max_total_bytes: (Number(el("vmQuota").value) || 128) * 1048576,
      retention_days: Number(el("vmRetention").value) || 0,
    },
  }).then(function (data) {
    state.voicemail = data.voicemail || {};
    renderVoicemail();
    var extra = el("vmEnabled").checked && !(state.engine || {}).enabled
      ? " 注意：服务端模式未开启，留言只在本页面打开时可用。" : "";
    notice("vmNotice", "ok", "已保存。" + extra);
  }).catch(function (error) {
    notice("vmNotice", "err", esc(error.message));
  }).then(function () { el("saveVoicemail").disabled = false; });
});

/* ---- SIP gateway ---- */
function renderSIP() {
  var settings = state.sip || {};
  el("sipEnabled").checked = !!settings.enabled;
  el("sipUser").value = settings.username || "";
  el("sipPass").value = settings.password || "";
  el("sipListen").value = settings.listen_address || "0.0.0.0:5060";
  el("sipAdvertise").value = settings.advertise_ip || "";
  el("sipSources").value = (settings.allowed_sources || []).join("\n");
  // Device options come from the same list the dialer uses; keep the saved
  // selection when the list has loaded after the settings did.
  var current = settings.device_id || "";
  el("sipDevice").innerHTML = (state.devices || []).map(function (device) {
    var label = device.name || device.id;
    if (device.name && device.id !== device.name) label += "（" + device.id + "）";
    return '<option value="' + esc(device.id) + '">' + esc(label) + "</option>";
  }).join("") || '<option value="">暂无设备</option>';
  if (current) el("sipDevice").value = current;
}

function renderSIPStatus(gateway) {
  var target = el("sipStatus");
  if (!gateway) { target.innerHTML = ""; return; }
  if (!gateway.enabled) {
    target.innerHTML = '<div class="notice err">网关未运行：' + esc(gateway.reason || "未启用") + "</div>";
    return;
  }
  var status = gateway.status || {};
  var lines = ['<div class="notice ok">网关运行中：' + esc(status.address || "") +
    " · 域 " + esc(status.realm || "") + " · 活跃通话 " + (status.active_calls || 0) + "</div>"];
  var bindings = status.bindings || [];
  if (!bindings.length) {
    lines.push('<div class="muted" style="font-size:12px">暂无软话机注册。手机端：服务器填运行插件的主机地址，' +
      "用户名/密码用上面配置的 SIP 账号，端口为监听地址里的端口。</div>");
  } else {
    lines.push("<table><thead><tr><th>联系人</th><th>来源</th><th>客户端</th><th>剩余有效期</th></tr></thead><tbody>" +
      bindings.map(function (binding) {
        return "<tr><td>" + esc(binding.contact) + "</td><td>" + esc(binding.target) + "</td><td>" +
          esc(binding.user_agent || "-") + "</td><td>" + (binding.expires_in || 0) + "s</td></tr>";
      }).join("") + "</tbody></table>");
  }
  target.innerHTML = lines.join("");
}

function loadSIPStatus() {
  request(BACKEND + "/sip/status").then(function (data) {
    renderSIPStatus(data.gateway);
  }).catch(function (error) {
    el("sipStatus").innerHTML = '<div class="notice err">' + esc(error.message) + "</div>";
  });
}

el("saveSIP").addEventListener("click", function () {
  notice("sipNotice", "", "");
  el("saveSIP").disabled = true;
  var sources = el("sipSources").value.split("\n").map(function (line) {
    return line.trim();
  }).filter(Boolean);
  request(BACKEND + "/sip/settings", {
    method: "PUT",
    body: {
      enabled: el("sipEnabled").checked,
      username: el("sipUser").value.trim(),
      password: el("sipPass").value,
      listen_address: el("sipListen").value.trim() || "0.0.0.0:5060",
      advertise_ip: el("sipAdvertise").value.trim(),
      device_id: el("sipDevice").value,
      allowed_sources: sources,
    },
  }).then(function (data) {
    state.sip = data.sip || {};
    el("sipPass").value = state.sip.password || "";
    renderSIP();
    renderSIPStatus(data.gateway);
    var extra = el("sipEnabled").checked && !(state.engine || {}).enabled
      ? " 注意：服务端模式未开启，网关不会启动。" : "";
    notice("sipNotice", "ok", "已保存并应用。" + extra);
  }).catch(function (error) {
    notice("sipNotice", "err", esc(error.message));
  }).then(function () { el("saveSIP").disabled = false; });
});

var pendingMessageDelete = "";

function loadMessages() {
  request(BACKEND + "/voicemail/messages").then(function (data) {
    state.messages = data.messages || [];
    renderMessages();
  }).catch(function (error) {
    el("messageList").innerHTML = '<div class="notice err">' + esc(error.message) + "</div>";
  });
}

function renderMessages() {
  if (!state.messages.length) {
    el("messageList").innerHTML = '<div class="empty">还没有留言。</div>';
    return;
  }
  var rows = state.messages.map(function (message, index) {
    var actions = message.id === pendingMessageDelete
      ? '<span class="muted">确认删除？</span> ' +
        '<button class="act small danger" data-act="confirm-del" data-i="' + index + '">删除</button> ' +
        '<button class="act small" data-act="cancel-del" data-i="' + index + '">取消</button>'
      : '<button class="act small" data-act="play" data-i="' + index + '">播放</button> ' +
        '<a class="act small" style="text-decoration:none;line-height:26px" download href="' +
          BACKEND + "/voicemail/messages/" + encodeURIComponent(message.id) + '/audio">下载</a> ' +
        '<button class="act small danger" data-act="del" data-i="' + index + '">删除</button>';
    return "<tr>" +
      "<td>" + (message.read ? '<span class="tag">已听</span>' : '<span class="tag ok">未听</span>') + "</td>" +
      "<td><strong>" + esc(message.contact_name || message.caller || "未知号码") + "</strong>" +
        '<div class="muted"><code>' + esc(message.caller) + "</code></div></td>" +
      "<td>" + esc(message.device_name || message.device_id) + "</td>" +
      "<td>" + formatSeconds(message.seconds) + "</td>" +
      "<td>" + new Date(message.created_at).toLocaleString() + "</td>" +
      '<td class="nowrap">' + actions + "</td></tr>";
  }).join("");
  el("messageList").innerHTML = "<table><thead><tr>" +
    "<th>状态</th><th>来电</th><th>设备</th><th>时长</th><th>时间</th><th>操作</th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>";

  var nodes = el("messageList").querySelectorAll("button[data-act]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("click", function (event) {
      var node = event.currentTarget;
      var message = state.messages[Number(node.getAttribute("data-i"))];
      if (!message) return;
      var action = node.getAttribute("data-act");
      if (action === "play") playMessage(message);
      else if (action === "del") { pendingMessageDelete = message.id; renderMessages(); }
      else if (action === "cancel-del") { pendingMessageDelete = ""; renderMessages(); }
      else if (action === "confirm-del") deleteMessage(message);
    });
  }
}

var audioPlayer = null;

function playMessage(message) {
  if (audioPlayer) audioPlayer.pause();
  audioPlayer = new Audio(BACKEND + "/voicemail/messages/" + encodeURIComponent(message.id) + "/audio");
  audioPlayer.play().then(function () {
    // Marking read only after playback starts avoids flagging a message the
    // browser could not actually play.
    return request(BACKEND + "/voicemail/messages/" + encodeURIComponent(message.id) + "/read",
      { method: "POST" });
  }).then(loadMessages).catch(function () {
    /* A missing file surfaces as a play failure; the list refresh is enough. */
  });
}

function deleteMessage(message) {
  request(BACKEND + "/voicemail/messages/" + encodeURIComponent(message.id), { method: "DELETE" })
    .then(function () { pendingMessageDelete = ""; loadMessages(); })
    .catch(function (error) { notice("vmNotice", "err", esc(error.message)); });
}

el("reloadMessages").addEventListener("click", loadMessages);

/* ---- notify ---- */
function renderNotify() {
  var config = state.notify || {};
  var webhook = config.webhook || {};
  var telegram = config.telegram || {};
  var pushplus = config.pushplus || {};
  el("whEnabled").checked = !!webhook.enabled;
  el("whURLs").value = (webhook.urls || []).join(", ");
  el("whSecret").value = webhook.secret || "";
  el("tgEnabled").checked = !!telegram.enabled;
  el("tgToken").value = telegram.bot_token || "";
  el("tgChat").value = telegram.chat_id || "";
  el("ppEnabled").checked = !!pushplus.enabled;
  el("ppToken").value = pushplus.token || "";
  el("ppTopic").value = pushplus.topic || "";

  var templates = config.templates && config.templates.length ? config.templates : state.defaults;
  var labels = {
    "call.incoming": "收到来电", "call.rejected": "已自动拒接", "call.answered": "已自动接听",
    "call.missed": "未接来电", "call.voicemail": "新语音留言", "keepalive.result": "保号任务结果",
  };
  var html = (state.eventNames.length ? state.eventNames : Object.keys(labels)).map(function (event) {
    var template = null;
    for (var i = 0; i < templates.length; i++) {
      if (templates[i].event === event) { template = templates[i]; break; }
    }
    if (!template) template = { event: event, enabled: false, title: "", body: "" };
    return '<div class="panel" style="background:transparent">' +
      '<div class="banner">' +
        '<label class="checkline"><input type="checkbox" data-tpl="enabled" data-event="' + event + '"' +
          (template.enabled ? " checked" : "") + " /> <strong>" + esc(labels[event] || event) +
          '</strong> <code>' + esc(event) + "</code></label>" +
        '<button class="act small" data-tpl="test" data-event="' + event + '">测试推送</button>' +
      "</div>" +
      '<div style="margin-top:8px"><label>标题</label>' +
        '<input type="text" data-tpl="title" data-event="' + event + '" value="' + esc(template.title) + '" /></div>' +
      '<div style="margin-top:8px"><label>正文</label>' +
        '<textarea data-tpl="body" data-event="' + event + '">' + esc(template.body) + "</textarea></div>" +
      '<div class="test-out" data-out="' + event + '"></div>' +
      "</div>";
  }).join("");
  el("templateList").innerHTML = html;

  var nodes = el("templateList").querySelectorAll("[data-tpl]");
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].getAttribute("data-tpl") === "test") {
      nodes[i].addEventListener("click", handleTemplateTest);
    } else {
      nodes[i].addEventListener("change", handleTemplateChange);
    }
  }
}

function templateFor(event) {
  if (!state.notify.templates) state.notify.templates = [];
  for (var i = 0; i < state.notify.templates.length; i++) {
    if (state.notify.templates[i].event === event) return state.notify.templates[i];
  }
  var created = { event: event, enabled: false, title: "", body: "" };
  // Seed from the backend defaults so enabling an event does not send a blank
  // message.
  for (var j = 0; j < state.defaults.length; j++) {
    if (state.defaults[j].event === event) {
      created.title = state.defaults[j].title;
      created.body = state.defaults[j].body;
      break;
    }
  }
  state.notify.templates.push(created);
  return created;
}

function handleTemplateChange(event) {
  var node = event.currentTarget;
  var template = templateFor(node.getAttribute("data-event"));
  var field = node.getAttribute("data-tpl");
  if (field === "enabled") template.enabled = node.checked;
  else template[field] = node.value;
}

function handleTemplateTest(event) {
  var node = event.currentTarget;
  var name = node.getAttribute("data-event");
  var output = el("templateList").querySelector('[data-out="' + name + '"]');
  node.disabled = true;
  output.innerHTML = '<div class="notice info">正在推送…</div>';
  // Save first: the backend renders from stored configuration, so an unsaved
  // edit would test the previous text.
  saveNotify(true).then(function () {
    return request(BACKEND + "/notify/test", { method: "POST", body: { event: name } });
  }).then(function (data) {
    var results = data.results || [];
    var lines = results.map(function (result) {
      return result.ok
        ? '<span class="tag ok">' + esc(result.channel) + " 成功</span>"
        : '<span class="tag err">' + esc(result.channel) + "</span> " + esc(result.error);
    });
    if (!lines.length) lines.push("没有启用任何推送通道。");
    var preview = data.preview || {};
    output.innerHTML = '<div class="notice ' + (results.length && results.every(function (r) { return r.ok; }) ? "ok" : "warn") + '">' +
      lines.join("<br>") + "</div>" +
      '<details open><summary>渲染结果</summary><div style="margin-top:6px"><strong>' +
      esc(preview.title || "") + "</strong><pre style=\"white-space:pre-wrap;margin:6px 0 0\">" +
      esc(preview.body || "") + "</pre></div></details>";
  }).catch(function (error) {
    output.innerHTML = '<div class="notice err">' + esc(error.message) + "</div>";
  }).then(function () { node.disabled = false; });
}

function collectNotify() {
  var urls = el("whURLs").value.split(",").map(function (value) { return value.trim(); })
    .filter(function (value) { return value !== ""; });
  return {
    webhook: { enabled: el("whEnabled").checked, urls: urls, secret: el("whSecret").value },
    telegram: {
      enabled: el("tgEnabled").checked,
      bot_token: el("tgToken").value,
      chat_id: el("tgChat").value.trim(),
    },
    pushplus: {
      enabled: el("ppEnabled").checked,
      token: el("ppToken").value,
      topic: el("ppTopic").value.trim(),
    },
    templates: state.notify.templates || [],
  };
}

function saveNotify(quiet) {
  return request(BACKEND + "/notify", { method: "PUT", body: collectNotify() })
    .then(function (data) {
      state.notify = data.notify || {};
      renderNotify();
      if (!quiet) notice("notifyNotice", "ok", "通知配置已保存。");
    }).catch(function (error) {
      notice("notifyNotice", "err", esc(error.message));
      throw error;
    });
}

el("saveNotify").addEventListener("click", function () {
  notice("notifyNotice", "", "");
  el("saveNotify").disabled = true;
  saveNotify(false).catch(function () {}).then(function () { el("saveNotify").disabled = false; });
});

/* ---- keepalive ---- */
function renderTasks() {
  if (!state.keepalive.length) {
    el("taskList").innerHTML = '<div class="empty">还没有保号任务。</div>';
    return;
  }
  var rows = state.keepalive.map(function (task, index) {
    var status = task.last_error
      ? '<span class="tag err">失败</span><div class="muted">' + esc(task.last_error) + "</div>"
      : task.last_status
        ? '<span class="tag ' + (task.last_status === "success" ? "ok" : "warn") + '">' +
          esc(task.last_status) + "</span><div class=\"muted\">" +
          new Date(task.last_run_at).toLocaleString() + "</div>"
        : '<span class="tag">未运行</span>';
    return "<tr>" +
      '<td><input type="checkbox" data-task="enabled" data-i="' + index + '"' +
        (task.enabled ? " checked" : "") + " /></td>" +
      '<td><input type="text" data-task="name" data-i="' + index + '" value="' + esc(task.name || "") + '" /></td>' +
      '<td><select data-task="device_id" data-i="' + index + '">' +
        deviceOptions(task.device_id, "请选择") + "</select></td>" +
      '<td><select data-task="kind" data-i="' + index + '">' +
        '<option value="call"' + (task.kind === "call" ? " selected" : "") + ">拨号</option>" +
        '<option value="sms"' + (task.kind === "sms" ? " selected" : "") + ">短信</option>" +
        "</select></td>" +
      '<td><input type="text" data-task="target" data-i="' + index + '" value="' + esc(task.target || "") + '" /></td>' +
      '<td><input type="text" data-task="message" data-i="' + index + '" value="' + esc(task.message || "") +
        '" placeholder="' + (task.kind === "sms" ? "短信内容" : "拨号不需要") + '"' +
        (task.kind === "sms" ? "" : " disabled") + " /></td>" +
      '<td><input type="number" min="1" max="600" data-task="duration_seconds" data-i="' + index + '" value="' +
        (task.duration_seconds || 20) + '" style="width:70px"' + (task.kind === "call" ? "" : " disabled") + " /></td>" +
      '<td><input type="number" min="1" max="8760" data-task="interval_hours" data-i="' + index + '" value="' +
        (task.interval_hours || 24) + '" style="width:70px" /></td>' +
      '<td><input type="number" min="0" max="8760" data-task="only_if_idle_hours" data-i="' + index + '" value="' +
        (task.only_if_idle_hours || 0) + '" style="width:70px" /></td>' +
      "<td>" + status + "</td>" +
      '<td class="nowrap"><button class="act small danger" data-task="del" data-i="' + index + '">删除</button></td>' +
      "</tr>";
  }).join("");
  el("taskList").innerHTML = "<table><thead><tr>" +
    "<th>启用</th><th>名称</th><th>设备</th><th>方式</th><th>目标</th><th>短信内容</th>" +
    "<th>通话(秒)</th><th>间隔(小时)</th><th>空闲(小时)</th><th>上次</th><th></th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>";

  var nodes = el("taskList").querySelectorAll("[data-task]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("change", handleTaskChange);
    if (nodes[i].tagName === "BUTTON") nodes[i].addEventListener("click", handleTaskChange);
  }
}

function handleTaskChange(event) {
  var node = event.currentTarget;
  var index = Number(node.getAttribute("data-i"));
  var field = node.getAttribute("data-task");
  var task = state.keepalive[index];
  if (!task) return;
  if (field === "del") { state.keepalive.splice(index, 1); renderTasks(); return; }
  if (field === "enabled") { task.enabled = node.checked; return; }
  if (field === "kind") { task.kind = node.value; renderTasks(); return; }
  if (node.type === "number") { task[field] = Number(node.value) || 0; return; }
  task[field] = node.value;
}

el("addTask").addEventListener("click", function () {
  state.keepalive.push({
    id: "", name: "", enabled: true, device_id: "", kind: "call",
    target: "", message: "", duration_seconds: 20, interval_hours: 24, only_if_idle_hours: 0,
  });
  renderTasks();
});

el("saveTasks").addEventListener("click", function () {
  notice("taskNotice", "", "");
  el("saveTasks").disabled = true;
  request(BACKEND + "/keepalive", { method: "PUT", body: { tasks: state.keepalive } })
    .then(function (data) {
      state.keepalive = data.keepalive || [];
      renderTasks();
      var extra = !(state.engine || {}).enabled
        ? " 注意：服务端模式未开启，保号任务不会自动运行。" : "";
      notice("taskNotice", "ok", "已保存。" + extra);
    }).catch(function (error) {
      notice("taskNotice", "err", esc(error.message));
    }).then(function () { el("saveTasks").disabled = false; });
});

/* ---- events ---- */
function loadEvents() {
  request(BACKEND + "/events?limit=200").then(function (data) {
    state.events = data.events || [];
    renderEvents();
  }).catch(function (error) {
    el("eventList").innerHTML = '<div class="notice err">' + esc(error.message) + "</div>";
  });
}

function renderEvents() {
  if (!state.events.length) {
    el("eventList").innerHTML = '<div class="empty">还没有处理记录。</div>';
    return;
  }
  var rows = state.events.map(function (event) {
    return "<tr>" +
      "<td>" + new Date(event.created_at).toLocaleString() + "</td>" +
      "<td><strong>" + esc(event.contact_name || event.caller || "未知号码") + "</strong>" +
        '<div class="muted"><code>' + esc(event.caller) + "</code></div></td>" +
      "<td>" + esc(event.device_name || event.device_id) + "</td>" +
      '<td><span class="tag">' + esc(event.action) + "</span></td>" +
      "<td>" + esc(event.rule_id || "默认") + "</td>" +
      "<td>" + (event.error
        ? '<span class="tag err">' + esc(event.outcome) + "</span><div class=\"muted\">" + esc(event.error) + "</div>"
        : '<span class="tag ok">' + esc(event.outcome) + "</span>") + "</td>" +
      "</tr>";
  }).join("");
  el("eventList").innerHTML = "<table><thead><tr>" +
    "<th>时间</th><th>来电</th><th>设备</th><th>动作</th><th>规则</th><th>结果</th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>";
}

el("reloadEvents").addEventListener("click", loadEvents);

/* ---- settings ---- */
function renderCredentials() {
  var credentials = state.credentials || {};
  el("credEnabled").checked = !!credentials.enabled;
  el("credUser").value = credentials.username || "";
  el("credPass").value = credentials.password || "";
  el("credBase").value = credentials.base_url || "https://127.0.0.1:7575";
  el("credCert").value = credentials.cert_path || "";
  el("credInsecure").checked = !!credentials.insecure_skip_verify;
}

el("saveCredentials").addEventListener("click", function () {
  notice("credNotice", "", "");
  el("saveCredentials").disabled = true;
  request(BACKEND + "/credentials", {
    method: "PUT",
    body: {
      enabled: el("credEnabled").checked,
      base_url: el("credBase").value.trim(),
      username: el("credUser").value.trim(),
      password: el("credPass").value,
      cert_path: el("credCert").value.trim(),
      insecure_skip_verify: el("credInsecure").checked,
    },
  }).then(function (data) {
    state.credentials = data.credentials || {};
    state.engine = data.engine || {};
    renderCredentials();
    renderBanner();
    if (data.warning) {
      notice("credNotice", "warn", "已保存，但连接 vocat 失败：" + esc(data.warning));
    } else if (state.engine.enabled) {
      notice("credNotice", "ok", "已保存并成功登录 vocat。");
    } else {
      notice("credNotice", "ok", "已保存，服务端模式关闭。");
    }
  }).catch(function (error) {
    notice("credNotice", "err", esc(error.message));
  }).then(function () { el("saveCredentials").disabled = false; });
});

/* ---- panel-mode rule execution ----
 *
 * When server-side mode is off, nothing in the backend can act on a call. This
 * loop makes the rules real while the page is open: it watches every device's
 * call list through vocat's own API and performs the decision with the
 * operator's session.
 */
var panelHandled = {};

function panelTick() {
  if ((state.engine || {}).enabled) return;
  if (!state.rules.length && state.fallback === "allow") return;
  if (document.hidden) return;

  (state.devices || []).forEach(function (device) {
    if (device.device_type === "wifi_410" || !device.running) return;
    request("/api/devices/" + encodeURIComponent(device.id) + "/calls")
      .then(function (snapshot) {
        if (snapshot.transport !== "vowifi") return;
        (snapshot.calls || []).forEach(function (call) {
          var key = device.id + "|" + call.id;
          if (call.state === "ended" || call.state === "failed") {
            delete panelHandled[key];
            return;
          }
          if (call.direction !== "incoming" || call.state !== "ringing") return;
          if (panelHandled[key]) return;
          panelHandled[key] = true;
          applyPanelDecision(device, call);
        });
      }).catch(function () { /* a transient read failure is not worth surfacing */ });
  });

  panelTickDrain();
}

function applyPanelDecision(device, call) {
  var key = device.id + "|" + call.id;
  request(BACKEND + "/rules/evaluate", {
    method: "POST", body: { device_id: device.id, number: call.number },
  }).then(function (decision) {
    if (decision.action === "allow") {
      if (decision.delay_seconds && decision.delay_seconds > 0) {
        var delayUntil = Date.now() + decision.delay_seconds * 1000;
        if (!state.pendingDelayed) state.pendingDelayed = [];
        state.pendingDelayed.push({
          key: key,
          device: device,
          call: call,
          decision: decision,
          delayUntil: delayUntil,
        });
        notice("ruleNotice", "info", "面板模式已排队延迟 " + decision.delay_seconds + " 秒后接听 " +
          esc(decision.contact_name || call.number));
        return null;
      }
      return request("/api/devices/" + encodeURIComponent(device.id) + "/calls/answer", {
        method: "POST", body: { call_id: call.id },
      }).then(function () {
        notice("ruleNotice", "ok", "面板模式已接听 " + esc(decision.contact_name || call.number));
        loadEvents();
      });
    }
    if (decision.action === "reject") {
      return request("/api/devices/" + encodeURIComponent(device.id) + "/calls/hangup", {
        method: "POST", body: { call_id: call.id },
      }).then(function () {
        notice("ruleNotice", "ok", "面板模式已拒接 " + esc(decision.contact_name || call.number));
        loadEvents();
      });
    }
    if (decision.action === "voicemail") {
      notice("ruleNotice", "warn", "规则要求转语音留言，但当前未开启服务端模式，无法执行留言动作（来电 " +
        esc(call.number) + "）已保持 ringing 状态。如需自动留言，请在电话助手设置中启用服务端模式。");
      return null;
    }
    return null;
  }).catch(function (error) {
    notice("ruleNotice", "err", "面板模式处理失败：" + esc(error.message));
  });
}

/* panelTick drains any queued delayed answers whose timer has elapsed so the
 * panel still acts on a delay rule even if the page was in the background when
 * it was queued. */
function panelTickDrain() {
  if (!state.pendingDelayed || !state.pendingDelayed.length) return;
  var due = [];
  var remaining = [];
  var now = Date.now();
  state.pendingDelayed.forEach(function (item) {
    if (now < item.delayUntil) {
      remaining.push(item);
      return;
    }
    due.push(item);
  });
  state.pendingDelayed = remaining;
  due.forEach(function (item) {
    if (panelHandled[item.key]) return;
    panelHandled[item.key] = true;
    request("/api/devices/" + encodeURIComponent(item.device.id) + "/calls/answer", {
      method: "POST", body: { call_id: item.call.id },
    }).then(function () {
      notice("ruleNotice", "ok", "面板模式延迟接听已执行 " + esc(item.decision.contact_name || item.call.number));
      loadEvents();
    }).catch(function (error) {
      notice("ruleNotice", "err", "面板模式延迟接听失败：" + esc(error.message));
    });
  });
}

/* ---- dialer, live calls and browser audio ---- */

var KEYPAD = [
  ["1", ""], ["2", "ABC"], ["3", "DEF"],
  ["4", "GHI"], ["5", "JKL"], ["6", "MNO"],
  ["7", "PQRS"], ["8", "TUV"], ["9", "WXYZ"],
  ["*", ""], ["0", "+"], ["#", ""],
];

/* activeAudio is the CallAudio for the call currently bridged to this browser.
 * Only one call can hold the microphone. */
var activeAudio = null;
var activeAudioCall = "";
var audioMuted = false;
var audioStatus = "idle";
var audioDetail = "";

function renderKeypad() {
  el("keypad").innerHTML = KEYPAD.map(function (pair) {
    return '<button type="button" data-key="' + pair[0] + '" aria-label="拨号键 ' + pair[0] + '">' +
      pair[0] + (pair[1] ? "<small>" + pair[1] + "</small>" : "") + "</button>";
  }).join("");
  var buttons = el("keypad").querySelectorAll("button[data-key]");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener("click", function (event) {
      var field = el("dialNumber");
      if (field.value.length < 32) field.value += event.currentTarget.getAttribute("data-key");
    });
  }
}

function renderDeviceSelectors() {
  el("dialDevice").innerHTML = (state.devices || []).map(function (device) {
    return '<option value="' + esc(device.id) + '">' + esc(device.name || device.id) + "</option>";
  }).join("") || '<option value="">没有可用设备</option>';
}

/* Mirrors the server's dial-number rule so the UI can refuse locally instead of
 * round-tripping a rejection: digits, a leading +, * and #, length 2-32. */
function validDialNumber(value) {
  if (value.length < 2 || value.length > 32) return false;
  for (var index = 0; index < value.length; index++) {
    var character = value[index];
    var isDigit = character >= "0" && character <= "9";
    if (isDigit || (index === 0 && character === "+") || character === "*" || character === "#") continue;
    return false;
  }
  return true;
}

function renderAudioBanner() {
  var support = window.CallAudio ? CallAudio.support() : { ok: false, reason: "unsupported" };
  if (support.ok) {
    el("audioBanner").innerHTML = "";
    return;
  }
  if (support.reason === "insecure-context") {
    el("audioBanner").innerHTML = '<div class="notice warn">' +
      "<strong>浏览器禁止在非安全来源访问麦克风，当前只能做信令控制（拨号、接听、挂断）。</strong>" +
      '<div style="margin-top:4px;font-size:12px">请通过 https:// 访问 vocat，' +
      "或用 <code>ssh -L 7575:127.0.0.1:7575</code> 端口转发后访问 http://localhost:7575。" +
      "用 IP 走 HTTP 时浏览器不会授予麦克风权限。</div></div>";
    return;
  }
  el("audioBanner").innerHTML = '<div class="notice warn">' +
    "当前浏览器不支持 Web Audio 或麦克风，只能做信令控制。</div>";
}

function loadLiveCalls() {
  var devices = (state.devices || []).filter(function (device) {
    return device.running && device.device_type !== "wifi_410";
  });
  if (!devices.length) {
    state.liveCalls = [];
    renderLiveCalls();
    return;
  }
  Promise.all(devices.map(function (device) {
    return request("/api/devices/" + encodeURIComponent(device.id) + "/calls")
      .then(function (snapshot) {
        return { device: device, snapshot: snapshot };
      })
      .catch(function () { return null; });
  })).then(function (results) {
    var calls = [];
    var anySuccess = false;
    results.forEach(function (result) {
      if (!result || !result.snapshot) return;
      anySuccess = true;
      // Only the VoWiFi transport reports a stable call id; the cellular
      // transport returns AT-derived integers that cannot be acted on.
      if (result.snapshot.transport !== "vowifi") return;
      (result.snapshot.calls || []).forEach(function (call) {
        if (call.state === "ended" || call.state === "failed") return;
        calls.push({ device: result.device, call: call });
      });
    });
    // A transient read failure is not worth severing browser audio that is
    // already bridged to a live call; keep the previous snapshot until the
    // next successful refresh.
    if (anySuccess) {
      state.liveCalls = calls;
    }
    renderLiveCalls();
    if (anySuccess) reconcileAudio();
  });
}

var STATE_LABEL = {
  dialing: "正在拨号", ringing: "响铃中", early_media: "早期媒体",
  active: "通话中", ended: "已结束", failed: "呼叫失败",
};

function callElapsed(call) {
  var reference = call.answered_at || call.started_at;
  if (!reference) return 0;
  var started = new Date(reference).getTime();
  if (isNaN(started)) return 0;
  return Math.max(0, Math.floor((Date.now() - started) / 1000));
}

function audioLabel() {
  switch (audioStatus) {
    case "connecting": return '<span class="tag warn">语音连接中</span>';
    case "live": return audioMuted
      ? '<span class="tag warn">已静音</span>'
      : '<span class="tag ok">语音已接通</span>';
    case "error": return '<span class="tag err">' + esc(audioDetail || "语音异常") + "</span>";
    default: return "";
  }
}

function renderLiveCalls() {
  if (!state.liveCalls.length) {
    el("liveCalls").innerHTML = '<div class="empty">没有进行中的通话。</div>';
    return;
  }
  var support = window.CallAudio ? CallAudio.support() : { ok: false };
  var html = state.liveCalls.map(function (entry, index) {
    var call = entry.call;
    var key = entry.device.id + "|" + call.id;
    var ringingInbound = call.direction === "incoming" && call.state === "ringing";
    var buttons = [];
    if (ringingInbound) {
      buttons.push('<button class="act small primary" data-call="answer" data-i="' + index + '">接听</button>');
    }
    buttons.push('<button class="act small danger" data-call="hangup" data-i="' + index + '">' +
      (ringingInbound ? "拒接" : "挂断") + "</button>");
    if (support.ok && call.state === "active" && call.media_ready) {
      if (activeAudioCall === key) {
        buttons.push('<button class="act small" data-call="mute" data-i="' + index + '">' +
          (audioMuted ? "取消静音" : "静音") + "</button>");
        buttons.push('<button class="act small" data-call="audio-stop" data-i="' + index + '">断开语音</button>');
      } else {
        buttons.push('<button class="act small" data-call="audio-start" data-i="' + index + '">接入语音</button>');
      }
    }
    return '<div class="callcard">' +
      "<div><strong>" + esc(call.number || "未知号码") + "</strong>" +
        (call.direction === "incoming" ? ' <span class="tag">来电</span>' : ' <span class="tag">去电</span>') +
        '<div class="dim">' + esc(entry.device.name || entry.device.id) + " · " +
        esc(STATE_LABEL[call.state] || call.state) +
        (call.codec ? " · " + esc(call.codec) : "") +
        (call.sip_code ? " · SIP " + call.sip_code : "") + "</div>" +
        (activeAudioCall === key ? '<div class="dim" style="margin-top:4px">' + audioLabel() + "</div>" : "") +
      "</div>" +
      '<div class="timer">' + formatSeconds(callElapsed(call)) + "</div>" +
      '<div class="nowrap">' + buttons.join(" ") + "</div>" +
      "</div>";
  }).join("");
  el("liveCalls").innerHTML = html;

  var nodes = el("liveCalls").querySelectorAll("button[data-call]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("click", function (event) {
      var node = event.currentTarget;
      var entry = state.liveCalls[Number(node.getAttribute("data-i"))];
      if (!entry) return;
      var action = node.getAttribute("data-call");
      if (action === "answer") answerCall(entry, node);
      else if (action === "hangup") hangupCall(entry, node);
      else if (action === "mute") toggleMute();
      else if (action === "audio-start") startAudio(entry);
      else if (action === "audio-stop") void stopAudio();
    });
  }
}

function answerCall(entry, node) {
  node.disabled = true;
  notice("dialNotice", "", "");
  request("/api/devices/" + encodeURIComponent(entry.device.id) + "/calls/answer", {
    method: "POST", body: { call_id: entry.call.id },
  }).then(function () {
    notice("dialNotice", "ok", "已接听 " + esc(entry.call.number || ""));
  }).catch(function (error) {
    notice("dialNotice", "err", esc(error.message));
  }).then(loadLiveCalls);
}

function hangupCall(entry, node) {
  node.disabled = true;
  notice("dialNotice", "", "");
  var key = entry.device.id + "|" + entry.call.id;
  var releasing = activeAudioCall === key ? stopAudio() : Promise.resolve();
  releasing.then(function () {
    return request("/api/devices/" + encodeURIComponent(entry.device.id) + "/calls/hangup", {
      method: "POST", body: { call_id: entry.call.id },
    });
  }).then(function () {
    notice("dialNotice", "ok", "已挂断。");
  }).catch(function (error) {
    notice("dialNotice", "err", esc(error.message));
  }).then(loadLiveCalls);
}

el("doDial").addEventListener("click", function () {
  var device = el("dialDevice").value;
  var number = el("dialNumber").value.trim();
  if (!device) { notice("dialNotice", "err", "请先选择设备。"); return; }
  if (!validDialNumber(number)) { notice("dialNotice", "err", "号码无效。"); return; }
  el("doDial").disabled = true;
  notice("dialNotice", "", "");
  request("/api/devices/" + encodeURIComponent(device) + "/calls/dial", {
    method: "POST", body: { number: number, duration_seconds: 0 },
  }).then(function () {
    notice("dialNotice", "ok", "已发起呼叫 " + esc(number));
    el("dialNumber").value = "";
  }).catch(function (error) {
    notice("dialNotice", "err", esc(error.message));
  }).then(function () {
    el("doDial").disabled = false;
    loadLiveCalls();
  });
});

el("doBackspace").addEventListener("click", function () {
  var field = el("dialNumber");
  field.value = field.value.slice(0, -1);
});

el("dialNumber").addEventListener("keydown", function (event) {
  if (event.key === "Enter") el("doDial").click();
});

el("reloadCalls").addEventListener("click", loadLiveCalls);

function startAudio(entry) {
  if (!window.CallAudio || !CallAudio.support().ok) return;
  var key = entry.device.id + "|" + entry.call.id;
  stopAudio().then(function () {
    var audio = new CallAudio({
      onStatus: function (status, detail) {
        audioStatus = status;
        audioDetail = detail || "";
        renderLiveCalls();
      },
    });
    activeAudio = audio;
    activeAudioCall = key;
    audioMuted = false;
    return audio.start(entry.device.id, entry.call.id);
  }).catch(function (error) {
    // The call itself is unaffected; only the browser audio path failed.
    notice("dialNotice", "err", "无法接通浏览器语音：" + esc(error.message));
    activeAudio = null;
    activeAudioCall = "";
    renderLiveCalls();
  });
}

function stopAudio() {
  var audio = activeAudio;
  activeAudio = null;
  activeAudioCall = "";
  audioMuted = false;
  audioStatus = "idle";
  audioDetail = "";
  if (!audio) return Promise.resolve();
  return audio.stop().catch(function () {});
}

function toggleMute() {
  if (!activeAudio) return;
  audioMuted = !audioMuted;
  activeAudio.setMuted(audioMuted);
  renderLiveCalls();
}

/* reconcileAudio releases the microphone when the bridged call is gone, so a
 * finished call never leaves the recording indicator on. A refresh failure
 * must not sever an already-bridged call, so it is only called after a
 * successful snapshot. */
function reconcileAudio() {
  if (!activeAudioCall) return;
  var stillLive = state.liveCalls.some(function (entry) {
    return entry.device.id + "|" + entry.call.id === activeAudioCall;
  });
  if (!stillLive) void stopAudio();
}

// Release the microphone if the operator closes or navigates away from the page.
window.addEventListener("beforeunload", function () { void stopAudio(); });

/* ---- call history ---- */

function loadHistory() {
  var params = [];
  if (state.historyFilter.direction) params.push("direction=" + encodeURIComponent(state.historyFilter.direction));
  if (state.historyFilter.missed) params.push("missed=1");
  if (state.historyFilter.recorded) params.push("recorded=1");
  params.push("limit=200");
  request(BACKEND + "/calls?" + params.join("&")).then(function (data) {
    state.history = data.calls || [];
    state.stats = data.stats || {};
    renderHistory();
  }).catch(function (error) {
    el("historyList").innerHTML = '<div class="notice err">' + esc(error.message) + "</div>";
  });
}

function formatBytes(bytes) {
  bytes = Number(bytes) || 0;
  if (!bytes) return "0 B";
  var units = ["B", "KB", "MB", "GB"];
  var exponent = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  var value = bytes / Math.pow(1024, exponent);
  return (value >= 10 || exponent === 0 ? Math.round(value) : value.toFixed(1)) + " " + units[exponent];
}

var pendingCallDelete = "";

function renderHistory() {
  var stats = state.stats || {};
  el("historyStats").textContent =
    "共 " + (stats.total || 0) + " 通　来电 " + (stats.incoming || 0) +
    "　去电 " + (stats.outgoing || 0) + "　未接 " + (stats.missed || 0) +
    "　录音 " + (stats.recorded || 0) + " 个 / " + formatBytes(stats.recording_bytes);

  el("filterMissed").className = "act small" + (state.historyFilter.missed ? " primary" : "");
  el("filterRecorded").className = "act small" + (state.historyFilter.recorded ? " primary" : "");

  if (!state.history.length) {
    el("historyList").innerHTML = '<div class="empty">还没有通话记录。</div>';
    return;
  }
  var rows = state.history.map(function (record, index) {
    var actions = record.id === pendingCallDelete
      ? '<span class="muted">确认删除？</span> ' +
        '<button class="act small danger" data-hist="confirm-del" data-i="' + index + '">删除</button> ' +
        '<button class="act small" data-hist="cancel-del" data-i="' + index + '">取消</button>'
      : (record.recording_path
          ? '<button class="act small" data-hist="play" data-i="' + index + '">播放</button> ' +
            '<a class="act small" style="text-decoration:none;line-height:26px" download href="' +
              BACKEND + "/calls/" + encodeURIComponent(record.id) + '/recording/audio">下载</a> ' +
            '<button class="act small" data-hist="del-rec" data-i="' + index + '">删录音</button> '
          : '<span class="dim" style="margin-right:6px">无录音</span>') +
        '<button class="act small danger" data-hist="del" data-i="' + index + '">删除</button>';
    var tag = record.missed
      ? '<span class="tag err">未接</span>'
      : record.answered
        ? '<span class="tag ok">已接通</span>'
        : '<span class="tag">' + esc(record.state || "-") + "</span>";
    return "<tr>" +
      "<td>" + (record.direction === "incoming" ? "← 来电" : "→ 去电") + "</td>" +
      "<td><strong>" + esc(record.contact_name || record.peer || "未知号码") + "</strong>" +
        '<div class="dim mono">' + esc(record.peer) + "</div></td>" +
      "<td>" + esc(record.device_name || record.device_id) + "</td>" +
      "<td>" + tag + (record.sip_code ? '<div class="dim">SIP ' + record.sip_code + "</div>" : "") + "</td>" +
      '<td class="mono">' + (record.duration_seconds ? formatSeconds(record.duration_seconds) : "--") + "</td>" +
      "<td>" + new Date(record.started_at).toLocaleString() + "</td>" +
      '<td class="nowrap">' + actions + "</td></tr>";
  }).join("");
  el("historyList").innerHTML = "<table><thead><tr>" +
    "<th>方向</th><th>号码</th><th>设备</th><th>状态</th><th>时长</th><th>时间</th><th>操作</th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>";

  var nodes = el("historyList").querySelectorAll("button[data-hist]");
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].addEventListener("click", function (event) {
      var node = event.currentTarget;
      var record = state.history[Number(node.getAttribute("data-i"))];
      if (!record) return;
      var action = node.getAttribute("data-hist");
      if (action === "play") playRecording(record);
      else if (action === "del") { pendingCallDelete = record.id; renderHistory(); }
      else if (action === "cancel-del") { pendingCallDelete = ""; renderHistory(); }
      else if (action === "confirm-del") deleteCallRecord(record);
      else if (action === "del-rec") deleteRecordingOnly(record);
    });
  }
}

var historyPlayer = null;

function playRecording(record) {
  if (historyPlayer) historyPlayer.pause();
  historyPlayer = new Audio(BACKEND + "/calls/" + encodeURIComponent(record.id) + "/recording/audio");
  historyPlayer.play().catch(function () {
    notice("historyNotice", "err", "录音无法播放，文件可能已被清理。");
    loadHistory();
  });
}

function deleteCallRecord(record) {
  request(BACKEND + "/calls/" + encodeURIComponent(record.id), { method: "DELETE" })
    .then(function () { pendingCallDelete = ""; loadHistory(); })
    .catch(function (error) { notice("historyNotice", "err", esc(error.message)); });
}

function deleteRecordingOnly(record) {
  request(BACKEND + "/calls/" + encodeURIComponent(record.id) + "/recording", { method: "DELETE" })
    .then(function () {
      notice("historyNotice", "ok", "录音已删除，通话记录保留。");
      loadHistory();
    })
    .catch(function (error) { notice("historyNotice", "err", esc(error.message)); });
}

el("reloadHistory").addEventListener("click", loadHistory);
el("historyDirection").addEventListener("change", function () {
  state.historyFilter.direction = el("historyDirection").value;
  loadHistory();
});
el("filterMissed").addEventListener("click", function () {
  state.historyFilter.missed = !state.historyFilter.missed;
  loadHistory();
});
el("filterRecorded").addEventListener("click", function () {
  state.historyFilter.recorded = !state.historyFilter.recorded;
  loadHistory();
});

/* ---- recording settings ---- */

function renderRecording() {
  var settings = state.recording || {};
  el("recEnabled").checked = !!settings.enabled;
  el("recDirection").value = settings.direction || "all";
  el("recMax").value = settings.max_seconds || 600;
  el("recQuota").value = Math.round((settings.max_total_bytes || 268435456) / 1048576);
  el("recRetention").value = settings.retention_days || 0;
}

el("saveRecording").addEventListener("click", function () {
  notice("recNotice", "", "");
  el("saveRecording").disabled = true;
  request(BACKEND + "/recording/settings", {
    method: "PUT",
    body: {
      enabled: el("recEnabled").checked,
      direction: el("recDirection").value,
      max_seconds: Number(el("recMax").value) || 600,
      max_total_bytes: (Number(el("recQuota").value) || 256) * 1048576,
      retention_days: Number(el("recRetention").value) || 0,
    },
  }).then(function (data) {
    state.recording = data.recording || {};
    state.stats = data.stats || state.stats;
    renderRecording();
    renderHistory();
    var extra = el("recEnabled").checked && !(state.engine || {}).enabled
      ? " 注意：服务端模式未开启，录音不会自动进行。" : "";
    notice("recNotice", "ok", "已保存。" + extra);
  }).catch(function (error) {
    notice("recNotice", "err", esc(error.message));
  }).then(function () { el("saveRecording").disabled = false; });
});

/* ---- bootstrap ---- */
function formatSeconds(seconds) {
  seconds = Number(seconds) || 0;
  return Math.floor(seconds / 60) + ":" + String(seconds % 60).padStart(2, "0");
}

function loadDevices() {
  return request("/api/devices").then(function (data) {
    state.devices = (data.devices || []).map(function (device) {
      return {
        id: device.id, name: device.name, running: device.running,
        device_type: device.deviceType || device.device_type,
      };
    });
    el("testDevice").innerHTML = deviceOptions("", "全部设备");
    // The SIP pane's device dropdown shares this list; refresh it if already rendered.
    if (typeof renderSIP === "function" && document.getElementById("sipDevice")) renderSIP();
  }).catch(function () {
    // The device list only drives dropdowns; the rest of the panel still works.
    state.devices = [];
  });
}

function loadAll() {
  return Promise.all([
    request(BACKEND + "/status"),
    request(BACKEND + "/config"),
    loadDevices(),
  ]).then(function (results) {
    var status = results[0] || {};
    var config = results[1] || {};
    state.defaults = status.defaults || [];
    state.eventNames = status.events || [];
    state.engine = config.engine || status.engine || {};
    state.rules = config.rules || [];
    state.fallback = config.fallback || "allow";
    state.contacts = config.contacts || [];
    state.voicemail = config.voicemail || {};
    state.notify = config.notify || { templates: [] };
    state.keepalive = config.keepalive || [];
    state.credentials = config.credentials || {};
    state.sip = config.sip || {};
    state.recording = config.recording || {};
    state.stats = config.stats || {};

    el("fallback").value = state.fallback;
    el("placeholderList").textContent =
      "{{caller}} {{contact}} {{device_name}} {{action}} {{rule}} {{duration}} {{result}} {{time}}";
    renderBanner();
    renderAudioBanner();
    renderKeypad();
    renderDeviceSelectors();
    renderRules();
    renderContacts();
    renderVoicemail();
    renderRecording();
    renderNotify();
    renderTasks();
    renderCredentials();
    renderSIP();
    loadLiveCalls();
  }).catch(function (error) {
    el("engineBanner").innerHTML = '<div class="notice err">加载失败：' + esc(error.message) + "</div>";
  });
}

loadAll();
window.setInterval(panelTick, POLL_MS);
// A separate, slower tick keeps the live-call card and its timer fresh without
// re-reading the whole configuration.
window.setInterval(function () {
  if (!document.hidden && el("paneDialer").className === "") loadLiveCalls();
}, 2000);
window.setInterval(function () {
  if (activeAudio) renderLiveCalls();
}, 1000);
