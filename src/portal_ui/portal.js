"use strict";
// The insurer portal: builds a scorecard from shared signed verdicts via POST /v2/verdict/scorecard.
// The licence token stays in memory and goes only into the Authorization header of that request.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var last = null;

  function setStatus(msg, isError) {
    var s = $("status");
    s.textContent = msg;
    s.className = isError ? "error" : "";
  }

  function parseVerdicts(text) {
    text = text.trim();
    if (!text) { return []; }
    if (text.charAt(0) === "[") { return JSON.parse(text); }
    return text.split(/\r?\n/).filter(function (l) { return l.trim(); }).map(function (l) { return JSON.parse(l); });
  }

  function cell(tr, text) {
    var td = document.createElement("td");
    td.textContent = text;
    tr.appendChild(td);
  }

  function render(env) {
    var v = env.verdict, s = v.verdict;
    last = v;
    $("summary").textContent = s.verdicts + (s.verdicts === 1 ? " shared verdict" : " shared verdicts") + " for " + s.subject + ". " + s.statement;
    var rows = $("rows");
    while (rows.firstChild) { rows.removeChild(rows.firstChild); }
    (s.methods || []).forEach(function (m) {
      var tr = document.createElement("tr");
      cell(tr, m.method);
      cell(tr, String(m.verdicts));
      cell(tr, m.first_utc);
      cell(tr, m.last_utc);
      cell(tr, Object.keys(m.outcomes || {}).map(function (k) { return k + " × " + m.outcomes[k]; }).join(", "));
      rows.appendChild(tr);
    });
    $("keyid").textContent = v.key_id;
    $("sha").textContent = v.verdict_sha256;
    $("result").hidden = false;
  }

  function go() {
    var token = $("token").value.trim();
    var subject = $("subject").value.trim();
    var verdicts;
    try { verdicts = parseVerdicts($("verdicts").value); }
    catch (e) { setStatus("The verdicts are not valid JSON: " + e.message, true); return; }
    if (!token) { setStatus("Paste your licence token.", true); return; }
    if (!subject) { setStatus("Name the subject.", true); return; }
    if (!verdicts.length) { setStatus("Paste or load the shared verdicts.", true); return; }
    $("go").disabled = true;
    setStatus("Checking the verdicts and building the scorecard…", false);
    fetch("/v2/verdict/scorecard", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify({ subject: subject, verdicts: verdicts }),
      credentials: "omit",
      cache: "no-store"
    }).then(function (r) {
      return r.json().then(function (j) { return { ok: r.ok, status: r.status, body: j }; });
    }).then(function (res) {
      if (!res.ok) { throw new Error((res.body && res.body.error) || ("HTTP " + res.status)); }
      render(res.body);
      setStatus("Done. The scorecard below is signed; save it to check it offline.", false);
    }).catch(function (e) {
      setStatus("Not built: " + e.message, true);
    }).then(function () { $("go").disabled = false; });
  }

  function save() {
    if (!last) { return; }
    var blob = new Blob([JSON.stringify(last, null, 2) + "\n"], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "scorecard.json";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  document.addEventListener("DOMContentLoaded", function () {
    $("go").addEventListener("click", go);
    $("save").addEventListener("click", save);
    $("file").addEventListener("change", function () {
      var f = this.files && this.files[0];
      if (!f) { return; }
      f.text().then(function (t) { $("verdicts").value = t; setStatus("Loaded " + f.name + ".", false); });
    });
  });
})();
