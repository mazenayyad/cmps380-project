// ----- steps -----
const steps = [
  "generate", "exchange", "derive", "encrypt", "sign", "send", "verify", "decrypt"
];
let current = 0;
let isBusy = false;
let cachedEnvelope = null;

// ----- explainer content (RSA mode, signature-only) -----
const HELP = {
  generate: {
    title: "Generate Keys",
    bullets: [
      "Each person makes TWO RSA-2048 keypairs: Signing (RSA-PSS) and Encryption (RSA-OAEP).",
      "Keys stay local; nothing secret is sent yet.",
      "Next we bind the encryption public keys to identities with signatures."
    ],
    terms: ["RSA-PSS (sign)", "RSA-OAEP (encrypt)"]
  },
  exchange: {
    title: "Exchange (bind encryption keys to identities)",
    bullets: [
      "Each side signs the HASH of its RSA-OAEP PUBLIC key with its identity PRIVATE key.",
      "The other side will verify this; a swapped key makes verification fail.",
      "After this, it’s safe to use Bob’s encryption public key."
    ],
    terms: ["Signature", "Verification", "MITM defense"]
  },
  derive: {
    title: "Establish Shared Key (Key Transport)",
    bullets: [
      "Alice creates a fresh 32-byte AES key for this message.",
      "She WRAPS it using Bob’s RSA-OAEP PUBLIC key—only Bob’s PRIVATE key can unwrap it.",
      "That AES key is the shared key used for AES-GCM."
    ],
    terms: ["AES-256 key", "Wrapped key", "OAEP"]
  },
  encrypt: {
    title: "Encrypt (AES-GCM)",
    bullets: [
      "Encrypt the note with AES-GCM using a fresh 12-byte NONCE (unique per key).",
      "Output is CIPHERTEXT + a 16-byte TAG (tamper-evident).",
      "AAD is context that’s authenticated but not hidden."
    ],
    terms: ["Nonce", "Ciphertext", "Tag", "AAD"]
  },
  sign: {
    title: "Sign the Envelope",
    bullets: [
      "Build the ENVELOPE JSON (wrapped key, nonce, AAD, ciphertext, tag, pubkeys…).",
      "Compute SHA-256 of that JSON (no signature field) and sign the digest with RSA-PSS.",
      "This proves origin (Alice) and detects any change."
    ],
    terms: ["SHA-256 digest", "Canonical JSON", "RSA-PSS"]
  },
  send: {
    title: "Send",
    bullets: [
      "This JSON is what would go over the network.",
      "Download or copy it. Try Tamper before Verify.",
      "Flip signature → Verify fails. Flip ciphertext → Decrypt fails."
    ],
    terms: ["Envelope", "Base64url", "Transport"]
  },
  verify: {
    title: "Verify",
    bullets: [
      "Recompute the same hash and check Alice’s RSA-PSS signature.",
      "If ANY field changed, verification fails here.",
      "Only after success do we decrypt."
    ],
    terms: ["Integrity", "Authenticity", "Verification"]
  },
  decrypt: {
    title: "Decrypt",
    bullets: [
      "Bob unwraps the AES key with his RSA-OAEP PRIVATE key.",
      "Then AES-GCM decrypts with nonce/AAD; mismatches cause an auth failure.",
      "On success you see the original plaintext."
    ],
    terms: ["RSA-OAEP unwrap", "AES-GCM", "Auth failure"]
  }
};

// ----- DOM helpers -----
const $ = sel => document.querySelector(sel);
const stepperUpdate = () => {
  const nodes = [...document.querySelectorAll(".stepper .step")];
  nodes.forEach((n, i) => {
    n.classList.toggle("active", i === current);
    n.classList.toggle("done", i < current);
  });
  $("#prevBtn").disabled = current === 0 || isBusy;
  $("#nextBtn").disabled = isBusy;
  $("#nextBtn").textContent = current === steps.length - 1 ? "Restart" : "Next →";
  $("#stepCount").textContent = `Step ${current + 1} of ${steps.length}`;
  const key = steps[current];
  const h = HELP[key];
  $("#helpTitle").textContent = h.title;
  fillBullets(h.bullets);
  fillTerms(h.terms);
};
const setStatus = (text, ok=true) => {
  const s = $("#status");
  s.textContent = text;
  s.classList.toggle("ok", ok);
  s.classList.toggle("bad", !ok);
};
const shortB64 = (b64, max=88) => b64 ? (b64.length > max ? b64.slice(0, max)+"…" : b64) : "—";
const show = (id, value, pulse=true) => {
  const el = document.getElementById(id);
  el.textContent = value || "—";
  if (pulse) { el.classList.remove("pulse"); void el.offsetWidth; el.classList.add("pulse"); }
};
const busy = (flag) => { isBusy = flag; stepperUpdate(); };

function fillBullets(items){
  const ul = $("#helpBullets");
  ul.innerHTML = "";
  items.forEach(t => { const li = document.createElement("li"); li.textContent = t; ul.appendChild(li); });
}
function fillTerms(items){
  const box = $("#helpTerms");
  box.innerHTML = "";
  items.forEach(t => { const b = document.createElement("span"); b.className = "term"; b.textContent = t; box.appendChild(b); });
}

// ----- network -----
async function jsonFetch(url, opts) {
  const res = await fetch(url, Object.assign({headers: {"Content-Type":"application/json"}}, opts || {}));
  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok || data.ok === false) throw new Error(data.error || "Request failed");
  return data;
}

// ----- copy handling -----
document.addEventListener("click", e => {
  if (e.target.matches(".copyable")) {
    const txt = e.target.textContent.trim();
    if (txt && txt !== "—") {
      navigator.clipboard.writeText(txt).then(()=>{
        const old = e.target.textContent;
        e.target.textContent = "Copied ✓";
        setTimeout(()=> e.target.textContent = old, 700);
      });
    }
  }
});

// ----- steps -----
async function doStep() {
  const name = steps[current];
  busy(true);
  try {
    if (name === "generate") {
      await jsonFetch("/api/reset");
      const r = await jsonFetch("/api/generate", {method: "POST"});
      show("aliceEnc", shortB64(r.alice.enc_pub_spki_b64));
      show("bobEnc",   shortB64(r.bob.enc_pub_spki_b64));
      setStatus("Keys generated ✓");
      $("#perf").textContent = "—";
    }
    else if (name === "exchange") {
      const r = await jsonFetch("/api/exchange", {method: "POST"});
      show("aliceEncSig", shortB64(r.alice_enc.signature_b64));
      show("bobEncSig",   shortB64(r.bob_enc.signature_b64));
      setStatus("Encryption keys exchanged and signed ✓");
    }
    else if (name === "derive") {
      const r = await jsonFetch("/api/derive", {method: "POST"});
      show("keyFp", r.shared_key_fingerprint);              // displayed as "AES key id (short hash)"
      show("wrappedKey", shortB64(r.wrapped_key_b64));
      setStatus("AES key generated and wrapped for Bob ✓");
    }
    else if (name === "encrypt") {
      const msg = $("#plaintext").value || "Hello from Alice!";
      const t0 = performance.now();
      const r = await jsonFetch("/api/encrypt", {method:"POST", body: JSON.stringify({plaintext: msg})});
      const ms = r.ms_encrypt ?? Math.round(performance.now() - t0);
      show("nonce", shortB64(r.nonce_b64));
      show("aad",   shortB64(r.aad_b64));
      show("ciphertext", shortB64(r.ciphertext_b64));
      show("tag", shortB64(r.tag_b64));
      $("#perf").textContent = `Encrypt: ${ms} ms • sha256(pt)=${r.plaintext_sha256_hex.slice(0,16)}…`;
      setStatus("Message encrypted ✓");
    }
    else if (name === "sign") {
      const r = await jsonFetch("/api/sign", {method:"POST"});
      cachedEnvelope = r.envelope;
      show("envHash", r.envelope.envelope_hash_hex.slice(0, 32) + "…");
      show("signature", shortB64(r.envelope.signature_b64));
      $("#perf").textContent = `Sign: ${r.ms_sign} ms`;
      setStatus("Envelope signed ✓");
    }
    else if (name === "send") {
      setStatus("Envelope ready. Download or copy it.");
    }
    else if (name === "verify") {
      if ($("#tamperCt").checked) {
        await jsonFetch("/api/tamper", {method:"POST", body: JSON.stringify({kind:"ciphertext"})});
        setStatus("Ciphertext tampered (1 byte flipped). Proceeding to verify…", false);
      }
      if ($("#tamperSig").checked) {
        await jsonFetch("/api/tamper", {method:"POST", body: JSON.stringify({kind:"signature"})});
        setStatus("Signature tampered (1 byte flipped). Proceeding to verify…", false);
      }
      const r = await jsonFetch("/api/verify", {method:"POST"});
      show("envHash", r.computed_hash_hex.slice(0, 32) + "…");
      setStatus("Signature verified ✓", true);
    }
    else if (name === "decrypt") {
      const r = await jsonFetch("/api/decrypt", {method:"POST"});
      setStatus("Decrypted ✓  →  " + r.plaintext, true);
    }
    stepDone();
  } catch (e) {
    setStatus(e.message || "Error", false);
  } finally {
    busy(false);
    window.scrollTo({top: 0, behavior: "smooth"});
  }
}

function stepDone() {
  if (current < steps.length - 1) current++;
  else {
    current = 0;
    jsonFetch("/api/reset").catch(()=>{});
    document.querySelectorAll("code.copyable").forEach(el => el.textContent = "—");
    $("#plaintext").value = "";
    $("#tamperCt").checked = false;
    $("#tamperSig").checked = false;
    $("#perf").textContent = "—";
    setStatus("Ready");
    cachedEnvelope = null;
  }
  stepperUpdate();
}

// controls
document.getElementById("nextBtn").addEventListener("click", async () => { if (!isBusy) await doStep(); });
document.getElementById("prevBtn").addEventListener("click", () => { if (!isBusy && current > 0) { current--; stepperUpdate(); }});
document.getElementById("resetBtn").addEventListener("click", async () => { if (!isBusy){ await jsonFetch("/api/reset"); location.reload(); }});
document.getElementById("themeBtn").addEventListener("click", () => {
  const html = document.documentElement;
  html.setAttribute("data-theme", html.getAttribute("data-theme")==="dark" ? "light" : "dark");
});

// presets
document.addEventListener("click", e => { if (e.target.matches(".presets .small")) $("#plaintext").value = e.target.dataset.preset; });

// copy envelope
document.getElementById("copyEnvBtn").addEventListener("click", async () => {
  if (!cachedEnvelope) return;
  await navigator.clipboard.writeText(JSON.stringify(cachedEnvelope, null, 2));
  setStatus("Envelope copied to clipboard ✓", true);
});

// init
stepperUpdate();
setStatus("Ready");