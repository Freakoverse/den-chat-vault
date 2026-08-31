# DEN Chat Vault

An **isolated signing origin** for DEN Chat. It generates, stores (encrypted), and
uses the Nostr private key entirely within its own origin, so the main app can only
ask it to sign via `postMessage` — an XSS in the app can never read the key.

This is a **separate deployment** from the app. It must live on its own origin
(e.g. `https://vault.denchat.top`), because the browser's isolation is per-origin.

## 1. Configure (before deploying)
Edit `src/main.ts`:
- `ALLOWED_PARENT_ORIGINS` → your app origin(s), e.g. `['https://web.denchat.top']`.
  Only these origins may message the vault.
Also update `frame-ancestors` in `index.html`'s CSP to the same app origin.

## 2. Build
```
npm install
npm run build      # outputs ./dist
```

## 3. Deploy to its own origin
**Option A — second GitHub Pages repo (recommended):**
1. New repo (e.g. `den-vault`); push this folder's contents (or the built `dist/`).
2. Repo → Settings → Pages: set **custom domain = `vault.denchat.top`** (writes a `CNAME`; GitHub provisions HTTPS).
3. DNS: add `CNAME  vault  →  <your-github-username>.github.io.`

**Option B — Cloudflare Pages / Netlify / Vercel (recommended for the anti-framing header):**
1. New project from this folder (build: `npm run build`, output `dist`).
2. Set custom domain `vault.denchat.top`; add the `CNAME` the host gives you.

HTTPS is mandatory (WebCrypto + secure-context). All hosts above provide it free on the custom domain.

> **Anti-framing header:** the CSP `frame-ancestors` directive that stops other origins from iframing the
> vault (and clickjacking the PIN / seed-reveal overlays) is **ignored in the `<meta>` tag** — browsers
> only honor it as a real HTTP response header. `public/_headers` sets it for Cloudflare Pages / Netlify;
> **GitHub Pages cannot set response headers**, so on Option A this protection is absent (the postMessage
> origin allowlist still blocks ops from non-allowlisted framers, but the overlay UI isn't clickjacking-
> protected). Prefer a header-capable host, and keep the `frame-ancestors` value in `public/_headers` in
> sync with `ALLOWED_PARENT_ORIGINS` in `src/main.ts`.

## 4. Verify it works on your device (the important step)
Open `https://vault.denchat.top/` **directly** (top-level) — on desktop, and then
**inside your installed iOS PWA** — and read the self-test. It checks key generation,
the encrypted-blob format, **IndexedDB persistence**, and signing in *this* context.

- All green → this origin can host the vault; we proceed to wire the app to it.
- "read back from IndexedDB" red **inside the installed PWA** → iOS is blocking the
  embedded origin's storage; we pivot to the Worker + password-manager approach.

## What's here vs. what's next
This is the vault core: key gen, the encrypted at-rest blob (same format as the app's
backup file — PBKDF2-SHA256 600k → AES-256-GCM), IndexedDB storage, escalating
rate-limited unlock, idle auto-lock, and the origin-allowlisted message protocol
(`status`, `generate`, `saveNew`, `importBackup`, `unlock`, `lock`, `getPublicKey`,
`signEvent`, `nip04/44Encrypt/Decrypt`, `exportBackup`, and the **NIP-SKD** sub-key
ops for private v2 hubs — `skdGetSubkeyPubkey`, `skdSignAsSubkey`,
`skdNip44Encrypt/DecryptAsSubkey` — which derive + act as the hub pseudonyms
(`O`/`P`/`Pf`) without the sub-key private material leaving this origin; byte-for-byte
identical to the app's reference derivation, checked against the NIP-SKD test vectors
in the self-test).

**Next phase (in the main app):** embed this iframe, a proxy signer that speaks the
protocol, the onboarding UI (generate → re-upload-to-verify backup → save), import
(file + QR), and Settings → Security PIN-gated QR/file export. Sensitive screens
(seed display, PIN entry) should render *inside* the visible vault iframe so the
seed/PIN never touch the app origin.
