import { decode, verify, sign } from "./codec.js";
import { parseKey } from "./keys.js";
import { annotateClaims, isExpired, isNotYetValid } from "./claims.js";

const SUPPORTED_ALGS = [
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA",
  "none",
];

const HMAC = (a) => a.startsWith("HS");

const state = {
  view: "decoder",
  token: "",
  alg: "HS256",
  keyText: "",
  base64Secret: false,
};

let decoderRunId = 0;

const left = () => document.getElementById("left");
const right = () => document.getElementById("right");

function escapeHTML(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function colouriseToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return escapeHTML(token);
  return (
    `<span class="seg-h">${escapeHTML(parts[0])}</span>` +
    `<span class="dot">.</span>` +
    `<span class="seg-p">${escapeHTML(parts[1])}</span>` +
    `<span class="dot">.</span>` +
    `<span class="seg-s">${escapeHTML(parts[2])}</span>`
  );
}

function renderDecoderViewSkeleton() {
  left().innerHTML = `
    <h2>Encoded</h2>
    <textarea id="encoded-input" spellcheck="false" autocomplete="off" placeholder="Paste your JWT here"></textarea>
    <pre id="encoded-display" aria-hidden="true"></pre>
  `;
  right().innerHTML = `
    <h2>Decoded</h2>
    <pre id="decoded-header">{}</pre>
    <pre id="decoded-payload">{}</pre>
    <div class="chips" id="status-chips" aria-live="polite" aria-atomic="true"></div>
    <div class="controls">
      <label>Algorithm
        <select id="alg-select"></select>
      </label>
      <label id="key-field-label">Secret
        <textarea id="key-input" spellcheck="false" autocomplete="off" placeholder="HS* secret, PEM, or JWK"></textarea>
      </label>
      <label class="row" id="base64-row">
        <input type="checkbox" id="base64-secret" /> secret is base64-encoded
      </label>
    </div>
  `;

  const sel = document.getElementById("alg-select");
  for (const a of SUPPORTED_ALGS) {
    const o = document.createElement("option");
    o.value = a; o.textContent = a;
    sel.appendChild(o);
  }
  sel.value = state.alg;

  document.getElementById("encoded-input").addEventListener("input", (e) => {
    state.token = e.target.value.trim();
    document.getElementById("encoded-display").innerHTML = colouriseToken(state.token);
    rerunDecoder();
  });
  sel.addEventListener("change", (e) => {
    state.alg = e.target.value;
    document.getElementById("base64-row").style.display = HMAC(state.alg) ? "" : "none";
    rerunDecoder();
  });
  document.getElementById("key-input").addEventListener("input", (e) => {
    state.keyText = e.target.value;
    rerunDecoder();
  });
  document.getElementById("base64-secret").addEventListener("change", (e) => {
    state.base64Secret = e.target.checked;
    rerunDecoder();
  });

  document.getElementById("base64-row").style.display = HMAC(state.alg) ? "" : "none";
}

async function rerunDecoder() {
  const myRun = ++decoderRunId;
  if (!state.token) {
    setText("decoded-header", "{}");
    setText("decoded-payload", "{}");
    setChips([]);
    return;
  }
  const d = decode(state.token);
  if (d.error) {
    setText("decoded-header", "{}");
    setText("decoded-payload", "{}");
    setChips([{ kind: "bad", label: "Malformed: " + d.error }]);
    return;
  }
  setText("decoded-header", JSON.stringify(d.header, null, 2));
  setText("decoded-payload", JSON.stringify(annotateClaims(d.payload), null, 2));

  const chips = [];
  if (d.header.alg === "none") chips.push({ kind: "warn", label: "Unsigned (alg=none)" });

  if (isNotYetValid(d.payload)) {
    chips.push({ kind: "warn", label: "Not yet valid (nbf > now)" });
  } else if (isExpired(d.payload)) {
    chips.push({ kind: "bad", label: "Expired" });
  } else {
    chips.push({ kind: "ok", label: "Within validity window" });
  }

  if (state.keyText && d.header.alg !== "none") {
    try {
      const key = await parseKey(state.keyText, state.alg, { base64: state.base64Secret });
      if (myRun !== decoderRunId) return;            // stale: newer run in flight
      const v = await verify(state.token, key);
      if (myRun !== decoderRunId) return;            // stale
      chips.unshift(v.ok ? { kind: "ok", label: "Signature ✓" } : { kind: "bad", label: "Signature ✗" });
    } catch (e) {
      if (myRun !== decoderRunId) return;
      chips.unshift({ kind: "bad", label: "Bad key: " + e.message });
    }
  } else if (d.header.alg !== "none") {
    chips.unshift({ kind: "warn", label: "No key supplied" });
  }
  if (myRun !== decoderRunId) return;
  setChips(chips);
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setChips(chips) {
  const el = document.getElementById("status-chips");
  if (!el) return;
  el.innerHTML = chips
    .map((c) => `<span class="chip ${c.kind}">${escapeHTML(c.label)}</span>`)
    .join("");
}

function renderEncoderViewSkeleton() {
  left().innerHTML = `
    <h2>Header / Payload</h2>
    <label>Algorithm
      <select id="enc-alg"></select>
    </label>
    <h2>Header JSON</h2>
    <textarea id="enc-header" spellcheck="false"></textarea>
    <h2>Payload JSON</h2>
    <textarea id="enc-payload" spellcheck="false"></textarea>
    <h2>Key / Secret</h2>
    <textarea id="enc-key" spellcheck="false" placeholder="HS* secret, PEM private key, or JWK"></textarea>
    <label class="row" id="enc-b64-row">
      <input type="checkbox" id="enc-base64" /> secret is base64-encoded
    </label>
    <button class="primary" id="enc-sign">Sign</button>
  `;
  right().innerHTML = `
    <h2>Encoded</h2>
    <pre id="enc-output">—</pre>
    <button class="primary" id="enc-copy">Copy</button>
  `;
  const algSel = document.getElementById("enc-alg");
  for (const a of SUPPORTED_ALGS) {
    const o = document.createElement("option");
    o.value = a; o.textContent = a;
    algSel.appendChild(o);
  }
  algSel.value = "HS256";
  document.getElementById("enc-header").value = JSON.stringify({ alg: "HS256", typ: "JWT" }, null, 2);
  document.getElementById("enc-payload").value = JSON.stringify({ sub: "1234567890", name: "Test", iat: Math.floor(Date.now() / 1000) }, null, 2);

  const updateB64Row = () => {
    document.getElementById("enc-b64-row").style.display = HMAC(algSel.value) ? "" : "none";
  };
  algSel.addEventListener("change", () => {
    const headerEl = document.getElementById("enc-header");
    try {
      const h = JSON.parse(headerEl.value);
      h.alg = algSel.value;
      headerEl.value = JSON.stringify(h, null, 2);
    } catch { /* user is mid-edit, leave it */ }
    updateB64Row();
  });
  updateB64Row();

  document.getElementById("enc-sign").addEventListener("click", async () => {
    const out = document.getElementById("enc-output");
    try {
      const header = JSON.parse(document.getElementById("enc-header").value);
      const payload = JSON.parse(document.getElementById("enc-payload").value);
      const keyText = document.getElementById("enc-key").value;
      const base64 = document.getElementById("enc-base64").checked;
      // sign() handles alg:"none" itself — no UI workaround needed.
      const key = header.alg === "none" ? null : await parseKey(keyText, header.alg, { base64 });
      const r = await sign(header, payload, key);
      out.textContent = r.error ? "Error: " + r.error : r.token;
    } catch (e) {
      out.textContent = "Error: " + e.message;
    }
  });
  document.getElementById("enc-copy").addEventListener("click", async () => {
    const t = document.getElementById("enc-output").textContent;
    // Clipboard API is allowed under our CSP (no network).
    try { await navigator.clipboard.writeText(t); } catch { /* ignored */ }
  });
}

export function bootstrap() {
  document.querySelectorAll(".mode-toggle button").forEach((b) => {
    b.addEventListener("click", () => switchView(b.dataset.view));
  });
  switchView("decoder");
}

function switchView(view) {
  state.view = view;
  document.querySelectorAll(".mode-toggle button").forEach((b) => {
    b.setAttribute("aria-pressed", b.dataset.view === view ? "true" : "false");
  });
  if (view === "decoder") renderDecoderViewSkeleton();
  else renderEncoderViewSkeleton();
}
