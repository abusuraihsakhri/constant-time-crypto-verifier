"use strict";

const runtimeStatus = document.getElementById("runtimeStatus");
const runTimingButton = document.getElementById("runTiming");
const runSourceButton = document.getElementById("runSource");
const class0Input = document.getElementById("class0Input");
const class1Input = document.getElementById("class1Input");
const sourceInput = document.getElementById("sourceInput");
let pyodide = null;

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("ctcv-theme", theme);
}

const savedTheme = localStorage.getItem("ctcv-theme");
setTheme(savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
document.getElementById("themeToggle").addEventListener("click", () => {
  setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const name = tab.dataset.tab;
    document.querySelectorAll(".tab").forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      const active = panel.dataset.panel === name;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });
  });
});

function parseSamples(value) {
  if (!value.trim()) return [];
  return value.trim().split(/[\s,;]+/).filter(Boolean).map((token) => Number(token));
}

function formatNumber(value, digits = 3) {
  if (value === null || value === undefined) return "undefined";
  return Number(value).toLocaleString(undefined, { maximumFractionDigits: digits });
}

function updateTimingCount() {
  const c0 = parseSamples(class0Input.value);
  const c1 = parseSamples(class1Input.value);
  const valid0 = c0.filter(Number.isFinite).length;
  const valid1 = c1.filter(Number.isFinite).length;
  document.getElementById("timingCount").textContent = `${valid0} vs ${valid1} samples`;
}
[class0Input, class1Input].forEach((input) => input.addEventListener("input", updateTimingCount));

function setTimingBadge(verdict) {
  const badge = document.getElementById("timingBadge");
  badge.className = "result-badge";
  if (verdict === "PASS_CONSTANT_TIME") {
    badge.classList.add("good");
    badge.textContent = "No signal";
  } else if (verdict === "SUSPICIOUS_MARGINAL") {
    badge.classList.add("warn");
    badge.textContent = "Inconclusive";
  } else {
    badge.classList.add("bad");
    badge.textContent = "Signal detected";
  }
}

async function runTiming() {
  const c0 = parseSamples(class0Input.value);
  const c1 = parseSamples(class1Input.value);
  if (c0.length < 2 || c1.length < 2 || [...c0, ...c1].some((value) => !Number.isFinite(value))) {
    document.getElementById("timingVerdict").textContent = "Enter at least two finite numeric samples in each class.";
    return;
  }
  runTimingButton.disabled = true;
  runTimingButton.textContent = "Analyzing…";
  try {
    pyodide.globals.set("class0_values", c0);
    pyodide.globals.set("class1_values", c1);
    const raw = await pyodide.runPythonAsync(`
import json
from dataclasses import asdict
from constant_time_crypto_verifier import ConstantTimeVerifierEngine
_result = ConstantTimeVerifierEngine.run_welch_t_test(class0_values.to_py(), class1_values.to_py())
json.dumps(asdict(_result), allow_nan=False)
`);
    const result = JSON.parse(raw);
    setTimingBadge(result.leakage_verdict);
    document.getElementById("tMetric").textContent = formatNumber(result.welch_t_statistic, 4);
    document.getElementById("dfMetric").textContent = formatNumber(result.degrees_of_freedom, 1);
    document.getElementById("diffMetric").textContent = `${formatNumber(result.max_timing_difference_ns, 3)} ns`;
    document.getElementById("nMetric").textContent = `${result.class0_stats.sample_size} / ${result.class1_stats.sample_size}`;
    document.getElementById("timingVerdict").textContent = result.leakage_verdict.replaceAll("_", " ").toLowerCase();
    document.getElementById("timingNote").textContent = result.confidence_level;
  } catch (error) {
    document.getElementById("timingVerdict").textContent = `Analysis failed: ${error.message || error}`;
  } finally {
    runTimingButton.disabled = false;
    runTimingButton.textContent = "Analyze timing";
  }
}

function addFinding(container, finding) {
  const item = document.createElement("div");
  item.className = "finding";
  const row = document.createElement("div");
  row.className = "finding-row";
  const title = document.createElement("strong");
  title.textContent = finding.vulnerability_type.replaceAll("_", " ");
  const meta = document.createElement("span");
  meta.textContent = `Line ${finding.line_number} · ${finding.severity}`;
  const detail = document.createElement("p");
  detail.textContent = finding.explanation;
  const code = document.createElement("code");
  code.textContent = finding.code_snippet;
  row.append(title, meta);
  item.append(row, detail, code);
  container.append(item);
}

async function runSource() {
  if (!sourceInput.value.trim()) {
    document.getElementById("sourceSummary").textContent = "Paste Python source before scanning.";
    return;
  }
  runSourceButton.disabled = true;
  runSourceButton.textContent = "Scanning…";
  const list = document.getElementById("findingList");
  try {
    pyodide.globals.set("scan_source", sourceInput.value);
    const raw = await pyodide.runPythonAsync(`
import json
from dataclasses import asdict
from constant_time_crypto_verifier import ConstantTimeVerifierEngine
_scan = ConstantTimeVerifierEngine.scan_source_code_ast(scan_source)
json.dumps(asdict(_scan), allow_nan=False)
`);
    const result = JSON.parse(raw);
    list.replaceChildren();
    const badge = document.getElementById("sourceBadge");
    badge.className = `result-badge ${result.total_findings ? "warn" : "good"}`;
    badge.textContent = result.total_findings ? `${result.total_findings} finding${result.total_findings === 1 ? "" : "s"}` : "No findings";
    document.getElementById("sourceSummary").textContent = result.total_findings
      ? "Review each heuristic finding in context."
      : "No configured timing-risk patterns were found in this source.";
    if (!result.vulnerabilities.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No configured patterns detected. This is not formal verification.";
      list.append(empty);
    } else {
      result.vulnerabilities.forEach((finding) => addFinding(list, finding));
    }
  } catch (error) {
    list.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = `Scan failed: ${error.message || error}`;
    list.append(empty);
  } finally {
    runSourceButton.disabled = false;
    runSourceButton.textContent = "Scan source";
  }
}

document.getElementById("timingExample").addEventListener("click", () => {
  class0Input.value = "100.2, 99.8, 100.6, 101.0, 99.7, 100.1, 100.4, 99.9, 100.0, 100.3";
  class1Input.value = "100.1, 100.0, 99.9, 100.5, 99.8, 100.2, 100.3, 99.7, 100.4, 100.0";
  updateTimingCount();
});

document.getElementById("sourceExample").addEventListener("click", () => {
  sourceInput.value = `def verify_token(secret_token, candidate):\n    for i in range(len(secret_token)):\n        if secret_token[i] != candidate[i]:\n            return False\n    return True\n`;
});
runTimingButton.addEventListener("click", runTiming);
runSourceButton.addEventListener("click", runSource);

async function initializeRuntime() {
  try {
    runtimeStatus.textContent = "Loading Python…";
    const indexURL = "https://cdn.jsdelivr.net/pyodide/v0.29.5/full/";
    pyodide = await loadPyodide({ indexURL });
    const response = await fetch("./constant_time_crypto_verifier.py", { cache: "no-cache" });
    if (!response.ok) throw new Error(`engine fetch returned ${response.status}`);
    const engineSource = await response.text();
    pyodide.FS.writeFile("/home/pyodide/constant_time_crypto_verifier.py", engineSource);
    await pyodide.runPythonAsync(`
import sys
if "/home/pyodide" not in sys.path:
    sys.path.insert(0, "/home/pyodide")
import constant_time_crypto_verifier
`);
    runtimeStatus.textContent = "Python ready";
    runtimeStatus.classList.add("ready");
    runTimingButton.disabled = false;
    runSourceButton.disabled = false;
  } catch (error) {
    runtimeStatus.textContent = "Runtime failed";
    runtimeStatus.classList.add("error");
    document.getElementById("timingVerdict").textContent = `Python runtime failed to load: ${error.message || error}`;
  }
}

window.addEventListener("load", initializeRuntime);
