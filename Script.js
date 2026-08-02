"use strict";

/* =========================================================
   Cipherguard — script.js
   Vanilla JS. No frameworks, no build step.
   ========================================================= */

/* ---------- Character sets ---------- */
const CHARSETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{};:,.<>/?~",
};
// Characters that are easy to misread (zero/O, one/l/I, etc.)
const AMBIGUOUS = "0O1lI|";

// A small list of extremely common passwords / patterns to flag outright.
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "123456789", "qwerty", "qwerty123",
  "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
  "football", "111111", "000000", "abc123", "password1", "1234567890",
  "sunshine", "princess", "login", "passw0rd", "trustno1", "starwars",
]);
const KEYBOARD_RUNS = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx"];

const HISTORY_KEY = "cipherguard_history_v1";
const THEME_KEY = "cipherguard_theme_v1";
const MAX_HISTORY = 20;

/* ---------- Element refs ---------- */
const $ = (id) => document.getElementById(id);

const els = {
  html: document.documentElement,
  themeToggle: $("themeToggle"),
  passwordField: $("passwordField"),
  readoutWrap: $("readoutWrap"),
  toggleVisibility: $("toggleVisibility"),
  regenBtn: $("regenBtn"),
  copyBtn: $("copyBtn"),
  copyToast: $("copyToast"),
  lengthSlider: $("lengthSlider"),
  lengthValue: $("lengthValue"),
  optUpper: $("optUpper"),
  optLower: $("optLower"),
  optNumbers: $("optNumbers"),
  optSymbols: $("optSymbols"),
  optAmbiguous: $("optAmbiguous"),
  generateBtn: $("generateBtn"),
  dialFill: $("dialFill"),
  dialNeedle: $("dialNeedle"),
  scoreLabel: $("scoreLabel"),
  bitsLabel: $("bitsLabel"),
  suggestionsList: $("suggestionsList"),
  historyList: $("historyList"),
  historyEmpty: $("historyEmpty"),
  clearHistoryBtn: $("clearHistoryBtn"),
};

/* =========================================================
   THEME
   ========================================================= */
function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  const theme = saved || (prefersLight ? "light" : "dark");
  applyTheme(theme);
}

function applyTheme(theme) {
  els.html.setAttribute("data-theme", theme);
  els.themeToggle.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
  els.themeToggle.setAttribute("aria-label", theme === "light" ? "Switch to dark mode" : "Switch to light mode");
  localStorage.setItem(THEME_KEY, theme);
}

els.themeToggle.addEventListener("click", () => {
  const current = els.html.getAttribute("data-theme");
  applyTheme(current === "dark" ? "light" : "dark");
});

/* =========================================================
   GENERATION
   ========================================================= */
function getSelectedSets() {
  const sets = [];
  if (els.optUpper.checked) sets.push(CHARSETS.upper);
  if (els.optLower.checked) sets.push(CHARSETS.lower);
  if (els.optNumbers.checked) sets.push(CHARSETS.numbers);
  if (els.optSymbols.checked) sets.push(CHARSETS.symbols);
  return sets;
}

function stripAmbiguous(str) {
  if (!els.optAmbiguous.checked) return str;
  return [...str].filter((c) => !AMBIGUOUS.includes(c)).join("");
}

// Cryptographically strong random index in [0, max)
function secureRandomIndex(max) {
  const arr = new Uint32Array(1);
  window.crypto.getRandomValues(arr);
  return arr[0] % max;
}

function generatePassword(length) {
  let sets = getSelectedSets().map(stripAmbiguous).filter((s) => s.length > 0);

  if (sets.length === 0) {
    // Nothing selected — fall back to lowercase so the app never produces an empty string
    sets = [stripAmbiguous(CHARSETS.lower)];
  }

  const allChars = sets.join("");
  const chars = [];

  // Guarantee at least one character from each selected set
  sets.forEach((set) => chars.push(set[secureRandomIndex(set.length)]));

  while (chars.length < length) {
    chars.push(allChars[secureRandomIndex(allChars.length)]);
  }

  // Fisher–Yates shuffle so guaranteed characters aren't always at the front
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.slice(0, length).join("");
}

function updateChipStyles() {
  document.querySelectorAll(".chip").forEach((chip) => {
    const input = chip.querySelector("input");
    chip.classList.toggle("is-checked", input.checked);
  });
}

function runGenerate() {
  const length = Number(els.lengthSlider.value);
  const pwd = generatePassword(length);
  els.passwordField.value = pwd;
  analyzeAndRender(pwd);
  saveToHistory(pwd);
  pulseReadout();
}

function pulseReadout() {
  els.readoutWrap.style.transform = "scale(1.012)";
  requestAnimationFrame(() => {
    els.readoutWrap.style.transition = "transform 0.22s ease";
    els.readoutWrap.style.transform = "scale(1)";
  });
  setTimeout(() => { els.readoutWrap.style.transition = ""; }, 250);
}

/* =========================================================
   STRENGTH ANALYSIS
   ========================================================= */
function poolSizeFor(password) {
  let size = 0;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[a-z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^A-Za-z0-9]/.test(password)) size += CHARSETS.symbols.length;
  return size || 1;
}

function hasSequentialRun(password, runLength = 3) {
  const lower = password.toLowerCase();
  for (let i = 0; i <= lower.length - runLength; i++) {
    let ascending = true;
    let descending = true;
    for (let j = 0; j < runLength - 1; j++) {
      const a = lower.charCodeAt(i + j);
      const b = lower.charCodeAt(i + j + 1);
      if (b - a !== 1) ascending = false;
      if (a - b !== 1) descending = false;
    }
    if (ascending || descending) return true;
  }
  return false;
}

function hasRepeatedRun(password, runLength = 3) {
  for (let i = 0; i <= password.length - runLength; i++) {
    const slice = password.slice(i, i + runLength);
    if (new Set(slice).size === 1) return true;
  }
  return false;
}

function containsKeyboardRun(password) {
  const lower = password.toLowerCase();
  return KEYBOARD_RUNS.some((run) => lower.includes(run));
}

function analyzePassword(password) {
  if (!password) {
    return { score: 0, bits: 0, label: "No password", tier: "idle", notes: [] };
  }

  const length = password.length;
  const pool = poolSizeFor(password);
  const bits = Math.round(length * Math.log2(pool));

  const notes = [];
  let penalty = 0;

  const isCommon = COMMON_PASSWORDS.has(password.toLowerCase());
  if (isCommon) {
    penalty += 45;
    notes.push({ tier: "bad", text: "This is one of the most commonly leaked passwords in the world — avoid it entirely." });
  }

  if (containsKeyboardRun(password)) {
    penalty += 20;
    notes.push({ tier: "bad", text: "Contains a keyboard-adjacent pattern (like \u201cqwerty\u201d), which crackers check first." });
  }

  if (hasSequentialRun(password)) {
    penalty += 15;
    notes.push({ tier: "warn", text: "Has a sequential run (e.g. abc, 321) — mix the order up." });
  }

  if (hasRepeatedRun(password)) {
    penalty += 15;
    notes.push({ tier: "warn", text: "Has 3+ repeated characters in a row, which weakens it more than it looks." });
  }

  if (length < 8) {
    penalty += 30;
    notes.push({ tier: "bad", text: "Shorter than 8 characters — brute-force tools crack these in moments." });
  } else if (length < 12) {
    penalty += 10;
    notes.push({ tier: "warn", text: "Under 12 characters. Aim for 12+ for comfortable long-term security." });
  }

  const typesUsed = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  if (typesUsed <= 1) {
    penalty += 25;
    notes.push({ tier: "bad", text: "Uses only one type of character. Combine letters, numbers and symbols." });
  } else if (typesUsed === 2) {
    penalty += 10;
    notes.push({ tier: "warn", text: "Uses only two character types — add numbers or symbols to widen the pool." });
  } else if (typesUsed >= 3) {
    notes.push({ tier: "good", text: "Good mix of character types — this widens the pool an attacker has to search." });
  }

  // Convert entropy bits into a 0–100 score, then apply pattern penalties.
  let score = Math.min(100, Math.round((bits / 100) * 100));
  score = Math.max(0, score - penalty);
  if (isCommon) score = Math.min(score, 5);

  let tier, label;
  if (score < 20) { tier = "weak"; label = "Very weak"; }
  else if (score < 40) { tier = "poor"; label = "Weak"; }
  else if (score < 60) { tier = "fair"; label = "Fair"; }
  else if (score < 80) { tier = "strong"; label = "Strong"; }
  else { tier = "excellent"; label = "Very strong"; }

  if (score >= 80 && notes.every((n) => n.tier !== "bad" && n.tier !== "warn")) {
    notes.unshift({ tier: "good", text: "Well distributed with no detectable patterns. Solid password." });
  }

  if (notes.length === 0) {
    notes.push({ tier: "good", text: "No issues detected." });
  }

  return { score, bits, label, tier, notes };
}

const TIER_COLORS = {
  weak: "var(--coral)",
  poor: "var(--coral)",
  fair: "var(--amber)",
  strong: "var(--teal)",
  excellent: "var(--green)",
};

function analyzeAndRender(password) {
  const result = analyzePassword(password);
  renderDial(result);
  renderSuggestions(result);
  return result;
}

function renderDial(result) {
  const circumference = 283; // approximate length of the semicircle path
  const offset = circumference - (circumference * result.score) / 100;
  els.dialFill.style.strokeDashoffset = offset;
  els.dialFill.style.stroke = TIER_COLORS[result.tier] || "var(--coral)";

  const angle = -90 + (result.score / 100) * 180;
  els.dialNeedle.style.transform = `rotate(${angle}deg)`;
  els.dialNeedle.style.stroke = TIER_COLORS[result.tier] || "var(--text)";

  if (result.tier === "idle") {
    els.scoreLabel.textContent = "Strength: —";
    els.scoreLabel.style.color = "var(--text)";
    els.bitsLabel.textContent = "Enter or generate a password to begin";
  } else {
    els.scoreLabel.textContent = `${result.label} · ${result.score}/100`;
    els.scoreLabel.style.color = TIER_COLORS[result.tier];
    els.bitsLabel.textContent = `~${result.bits} bits of entropy`;
  }
}

function renderSuggestions(result) {
  els.suggestionsList.innerHTML = "";

  if (result.tier === "idle") {
    const li = document.createElement("li");
    li.className = "suggestion suggestion--idle";
    li.textContent = "Your security notes will show up here once there's a password to check.";
    els.suggestionsList.appendChild(li);
    return;
  }

  result.notes.forEach((note) => {
    const li = document.createElement("li");
    li.className = `suggestion suggestion--${note.tier}`;
    const dot = document.createElement("span");
    dot.className = "suggestion__dot";
    const text = document.createElement("span");
    text.textContent = note.text;
    li.appendChild(dot);
    li.appendChild(text);
    els.suggestionsList.appendChild(li);
  });
}

/* =========================================================
   HISTORY (localStorage)
   ========================================================= */
function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function writeHistory(list) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_HISTORY)));
}

function saveToHistory(password) {
  if (!password) return;
  const list = loadHistory();

  // Avoid stacking an identical duplicate at the top
  if (list[0] && list[0].password === password) return;

  const result = analyzePassword(password);
  list.unshift({
    password,
    tier: result.tier,
    label: result.label,
    score: result.score,
    createdAt: Date.now(),
  });

  writeHistory(list);
  renderHistory();
}

function relativeTime(ts) {
  const diffSec = Math.max(1, Math.round((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}

function renderHistory() {
  const list = loadHistory();
  els.historyList.querySelectorAll(".history-item").forEach((n) => n.remove());
  els.historyEmpty.style.display = list.length ? "none" : "block";

  list.forEach((entry, index) => {
    const li = document.createElement("li");
    li.className = "history-item";
    li.dataset.index = String(index);

    const bar = document.createElement("span");
    bar.className = "history-item__strength";
    bar.style.background = TIER_COLORS[entry.tier] || "var(--muted)";

    const body = document.createElement("div");
    body.className = "history-item__body";
    const passSpan = document.createElement("div");
    passSpan.className = "history-item__pass";
    passSpan.textContent = entry.password;
    const meta = document.createElement("div");
    meta.className = "history-item__meta";
    meta.textContent = `${entry.label} · ${relativeTime(entry.createdAt)}`;
    body.appendChild(passSpan);
    body.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "history-item__actions";

    const revealBtn = document.createElement("button");
    revealBtn.className = "icon-btn";
    revealBtn.type = "button";
    revealBtn.title = "Show / hide";
    revealBtn.setAttribute("aria-label", "Show or hide this password");
    revealBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>`;
    revealBtn.addEventListener("click", () => li.classList.toggle("revealed"));

    const copyBtn = document.createElement("button");
    copyBtn.className = "icon-btn";
    copyBtn.type = "button";
    copyBtn.title = "Copy";
    copyBtn.setAttribute("aria-label", "Copy this password");
    copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="12" height="12" rx="2" stroke="currentColor" stroke-width="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`;
    copyBtn.addEventListener("click", () => copyText(entry.password));

    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn";
    delBtn.type = "button";
    delBtn.title = "Delete";
    delBtn.setAttribute("aria-label", "Delete this entry");
    delBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2m-9 0 1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    delBtn.addEventListener("click", () => deleteHistoryEntry(index));

    actions.appendChild(revealBtn);
    actions.appendChild(copyBtn);
    actions.appendChild(delBtn);

    li.appendChild(bar);
    li.appendChild(body);
    li.appendChild(actions);
    els.historyList.appendChild(li);
  });
}

function deleteHistoryEntry(index) {
  const list = loadHistory();
  list.splice(index, 1);
  writeHistory(list);
  renderHistory();
}

els.clearHistoryBtn.addEventListener("click", () => {
  if (loadHistory().length === 0) return;
  const confirmed = window.confirm("Clear the entire password log? This can't be undone.");
  if (confirmed) {
    writeHistory([]);
    renderHistory();
  }
});

/* =========================================================
   COPY TO CLIPBOARD
   ========================================================= */
async function copyText(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for environments without Clipboard API access
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.select();
    document.execCommand("copy");
    document.body.removeChild(temp);
  }
  showCopyToast();

  // If a custom/typed password gets copied and wasn't logged yet, log it now.
  const list = loadHistory();
  if (!list.some((e) => e.password === text)) {
    saveToHistory(text);
  }
}

function showCopyToast() {
  els.copyToast.classList.add("show");
  clearTimeout(showCopyToast._t);
  showCopyToast._t = setTimeout(() => els.copyToast.classList.remove("show"), 1400);
}

/* =========================================================
   EVENT WIRING
   ========================================================= */
els.lengthSlider.addEventListener("input", () => {
  els.lengthValue.textContent = els.lengthSlider.value;
});

[els.optUpper, els.optLower, els.optNumbers, els.optSymbols].forEach((el) => {
  el.addEventListener("change", updateChipStyles);
});

els.generateBtn.addEventListener("click", runGenerate);
els.regenBtn.addEventListener("click", runGenerate);

els.toggleVisibility.addEventListener("click", () => {
  const nowVisible = els.readoutWrap.classList.toggle("readout--visible");
  els.toggleVisibility.setAttribute("aria-pressed", String(nowVisible));
  els.toggleVisibility.setAttribute("aria-label", nowVisible ? "Hide password" : "Show password");
});

els.copyBtn.addEventListener("click", () => copyText(els.passwordField.value));

// Live-analyze whatever the user types manually into the readout
let typingTimer = null;
els.passwordField.addEventListener("input", () => {
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => analyzeAndRender(els.passwordField.value), 120);
});

/* =========================================================
   INIT
   ========================================================= */
function init() {
  initTheme();
  updateChipStyles();
  renderHistory();
  analyzeAndRender("");
  els.lengthValue.textContent = els.lengthSlider.value;
  runGenerate(); // seed with an initial password so the dial isn't empty on load
}

init();