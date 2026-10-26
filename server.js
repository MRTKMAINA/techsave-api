// TechSave — cobalt-style media saver backend (zero dependencies, Node 22+).
// API contract mirrors cobalt's POST / -> {status: tunnel|redirect|picker|error}.
// Architecture reference: imputnet/cobalt (AGPL-3.0). This is an independent
// implementation; if you reuse cobalt code verbatim, AGPL-3.0 obligations apply.
import http from "node:http";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import dns from "node:dns/promises";
import net from "node:net";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dir = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const BASE = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const UPSTREAM = process.env.UPSTREAM_COBALT || ""; // optional self-hosted cobalt instance
const UPSTREAM_KEY = process.env.UPSTREAM_API_KEY || "";
const TTL_MS = 120_000;
const RATE = { windowMs: 60_000, max: Number(process.env.RATE_MAX || 20) };

const ENUMS = {
  downloadMode: ["auto", "audio", "mute"],
  audioFormat: ["best", "mp3", "ogg", "wav", "opus"],
  audioBitrate: ["320", "256", "128", "96", "64", "8"],
  videoQuality: ["max", "4320", "2160", "1440", "1080", "720", "480", "360", "240", "144"],
  filenameStyle: ["classic", "pretty", "basic", "nerdy"],
};
const DEFAULTS = { downloadMode: "auto", audioFormat: "mp3", audioBitrate: "128", videoQuality: "1080", filenameStyle: "basic", disableMetadata: false };

// ---------- schema ----------
function parseBody(b) {
  if (!b || typeof b !== "object" || typeof b.url !== "string" || !b.url.trim()) return { error: "error.api.link.missing" };
  let url;
  try { url = new URL(b.url.trim()); } catch { return { error: "error.api.link.invalid" }; }
  if (!/^https?:$/.test(url.protocol)) return { error: "error.api.link.unsupported" };
  const out = { ...DEFAULTS, url };
  for (const [k, allowed] of Object.entries(ENUMS)) {
    if (b[k] === undefined) continue;
    if (!allowed.includes(String(b[k]))) return { error: `error.api.invalid_body` };
    out[k] = String(b[k]);
  }
  if (b.disableMetadata !== undefined) out.disableMetadata = !!b.disableMetadata;
  return { value: out };
}

// ---------- SSRF guard ----------
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  const l = ip.toLowerCase();
  return l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80") || l.startsWith("::ffff:");
}
async function assertPublic(urlStr) {
  if (process.env.ALLOW_PRIVATE === "1") return; // for local testing only
  const u = new URL(urlStr);
  if (net.isIP(u.hostname)) { if (isPrivateIP(u.hostname)) throw new Error("private"); return; }
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIP(a.address))) throw new Error("private");
}

// ---------- extractors (service adapters) ----------
const MEDIA_EXT = /\.(mp4|webm|mkv|mov|m4v|mp3|m4a|ogg|opus|wav|flac|gif|jpe?g|png|webp)(\?|$)/i;
const slug = s => s.replace(/[^\w.-]+/g, "_").slice(0, 80);

const services = [
  {
    name: "streamable",
    match: u => /(^|\.)streamable\.com$/.test(u.hostname) && u.pathname.length > 1,
    async run(u, o) {
      const id = u.pathname.split("/").filter(Boolean).pop();
      const r = await fetch(`https://api.streamable.com/videos/${encodeURIComponent(id)}`);
      if (!r.ok) return { error: "error.api.fetch.empty" };
      const v = await r.json();
      const want = o.videoQuality === "max" || Number(o.videoQuality) >= 720;
      const f = (want && v.files?.mp4) || v.files?.["mp4-mobile"] || v.files?.mp4;
      if (!f?.url) return { error: "error.api.fetch.fail" };
      return { url: f.url.startsWith("//") ? "https:" + f.url : f.url, filename: `streamable_${id}.mp4`, title: v.title, kind: "video" };
    },
  },
  {
    name: "direct",
    match: u => MEDIA_EXT.test(u.pathname + u.search),
    async run(u) {
      const name = decodeURIComponent(u.pathname.split("/").pop() || "file");
      const ext = (name.match(/\.(\w+)$/) || [])[1]?.toLowerCase() || "";
      const kind = /^(mp3|m4a|ogg|opus|wav|flac)$/.test(ext) ? "audio" : /^(jpe?g|png|webp|gif)$/.test(ext) ? "image" : "video";
      return { url: u.toString(), filename: slug(name), kind };
    },
  },
];

async function viaUpstream(body) {
  const r = await fetch(UPSTREAM, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", ...(UPSTREAM_KEY ? { Authorization: `Api-Key ${UPSTREAM_KEY}` } : {}) },
    body: JSON.stringify(body),
  });
  return r.json();
}

// ---------- tunnels ----------
const tunnels = new Map();
const sweep = setInterval(() => { const n = Date.now(); for (const [k, v] of tunnels) if (v.exp < n) tunnels.delete(k); }, 30_000);
sweep.unref();

function baseOf(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL;
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return host ? `${String(proto).split(",")[0]}://${host}` : BASE;
}
function createTunnel(spec, req) {
  const id = randomBytes(18).toString("base64url");
  tunnels.set(id, { ...spec, exp: Date.now() + TTL_MS });
  return `${baseOf(req)}/tunnel?id=${id}`;
}

const AUDIO_MIME = { mp3: "audio/mpeg", ogg: "audio/ogg", wav: "audio/wav", opus: "audio/ogg" };
const AUDIO_CODEC = { mp3: ["libmp3lame", "mp3"], ogg: ["libvorbis", "ogg"], wav: ["pcm_s16le", "wav"], opus: ["libopus", "ogg"] };

async function handleProcess(req, res, raw) {
  let json;
  try { json = JSON.parse(raw); } catch { return send(res, 400, err("error.api.invalid_body")); }
  const p = parseBody(json);
  if (p.error) return send(res, 400, err(p.error));
  const o = p.value;

  if (UPSTREAM) return send(res, 200, await viaUpstream(json).catch(() => err("error.api.fetch.critical")));

  const svc = services.find(s => s.match(o.url));
  if (!svc) return send(res, 200, err("error.api.link.unsupported"));
  let r;
  try { r = await svc.run(o.url, o); } catch { return send(res, 200, err("error.api.fetch.critical")); }
  if (r.error) return send(res, 200, err(r.error));
  try { await assertPublic(r.url); } catch { return send(res, 200, err("error.api.link.blocked")); }

  const base = r.filename.replace(/\.\w+$/, "");
  const audioOnly = o.downloadMode === "audio" || r.kind === "audio" && o.downloadMode !== "mute";
  if (r.kind === "image" || (r.kind === "video" && o.downloadMode === "auto") || (r.kind === "audio" && o.audioFormat === "best")) {
    return send(res, 200, { status: "tunnel", url: createTunnel({ mode: "proxy", src: r.url }, req), filename: r.filename });
  }
  if (audioOnly) {
    const fmt = o.audioFormat === "best" ? "mp3" : o.audioFormat;
    const fname = `${base}.${fmt === "opus" ? "opus" : fmt}`;
    return send(res, 200, { status: "tunnel", url: createTunnel({ mode: "audio", src: r.url, fmt, bitrate: o.audioBitrate, title: o.disableMetadata ? null : r.title, filename: fname }, req), filename: fname });
  }
  // mute
  const fname = `${base}_mute.mp4`;
  return send(res, 200, { status: "tunnel", url: createTunnel({ mode: "mute", src: r.url, filename: fname }, req), filename: fname });
}

async function handleTunnel(req, res, id) {
  const t = tunnels.get(id);
  if (!t || t.exp < Date.now()) return send(res, 404, err("error.api.stream.not_found"));
  const cd = `attachment; filename="${(t.filename || "file").replace(/["\r\n]/g, "")}"`;
  if (t.mode === "proxy") {
    try {
      await assertPublic(t.src);
      const up = await fetch(t.src, { headers: req.headers.range ? { Range: req.headers.range } : {}, redirect: "follow" });
      res.writeHead(up.status, {
        "Content-Type": up.headers.get("content-type") || "application/octet-stream",
        ...(up.headers.get("content-length") ? { "Content-Length": up.headers.get("content-length") } : {}),
        ...(up.headers.get("accept-ranges") ? { "Accept-Ranges": up.headers.get("accept-ranges") } : {}),
        "Content-Disposition": cd, "Cross-Origin-Resource-Policy": "cross-origin",
      });
      if (!up.body) return res.end();
      const reader = up.body.getReader();
      res.on("close", () => reader.cancel().catch(() => {}));
      for (;;) { const { done, value } = await reader.read(); if (done) break; if (!res.write(value)) await new Promise(r => res.once("drain", r)); }
      return res.end();
    } catch { return res.headersSent ? res.destroy() : send(res, 502, err("error.api.fetch.fail")); }
  }
  // ffmpeg modes
  const args = ["-hide_banner", "-loglevel", "error", "-i", t.src];
  if (t.mode === "audio") {
    const [codec, container] = AUDIO_CODEC[t.fmt];
    args.push("-vn", "-c:a", codec);
    if (t.fmt !== "wav") args.push("-b:a", `${t.bitrate}k`);
    if (t.title) args.push("-metadata", `title=${t.title}`);
    args.push("-f", container, "pipe:1");
    res.writeHead(200, { "Content-Type": AUDIO_MIME[t.fmt], "Content-Disposition": cd });
  } else {
    args.push("-an", "-c:v", "copy", "-movflags", "frag_keyframe+empty_moov", "-f", "mp4", "pipe:1");
    res.writeHead(200, { "Content-Type": "video/mp4", "Content-Disposition": cd });
  }
  const ff = spawn(process.env.FFMPEG_PATH || "ffmpeg", args, { stdio: ["ignore", "pipe", "ignore"] });
  ff.stdout.pipe(res);
  res.on("close", () => ff.kill("SIGKILL"));
  ff.on("error", () => res.destroy());
}

// ---------- http plumbing ----------
const err = code => ({ status: "error", error: { code } });
function send(res, code, obj, extra = {}) {
  res.writeHead(code, { "Content-Type": "application/json", ...cors(), ...extra });
  res.end(JSON.stringify(obj));
}
const cors = () => ({ "Access-Control-Allow-Origin": process.env.CORS_ORIGIN || "*", "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization", "Access-Control-Allow-Methods": "GET, POST, OPTIONS" });

const hits = new Map();
function limited(ip) {
  const n = Date.now(); const h = (hits.get(ip) || []).filter(t => n - t < RATE.windowMs);
  h.push(n); hits.set(ip, h); return h.length > RATE.max;
}

const handler = async (req, res) => {
  const u = new URL(req.url, BASE);
  try {
    if (req.method === "OPTIONS") { res.writeHead(204, cors()); return res.end(); }
    if (req.method === "GET" && (u.pathname === "/" || u.pathname === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(await readFile(path.join(__dir, "index.html")));
    }
    if (req.method === "GET" && u.pathname === "/api/info") {
      return send(res, 200, { name: "techsave", version: "0.1.0", upstream: !!UPSTREAM, services: services.map(s => s.name), options: ENUMS });
    }
    if (req.method === "GET" && u.pathname === "/tunnel") return handleTunnel(req, res, u.searchParams.get("id") || "");
    if (req.method === "POST" && u.pathname === "/api") {
      const ip = req.headers["cf-connecting-ip"] || String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "?";
      if (limited(ip)) return send(res, 429, err("error.api.rate_exceeded"), { "Retry-After": "60" });
      if (!(req.headers["content-type"] || "").includes("application/json")) return send(res, 400, err("error.api.header.content_type"));
      // Cloud Functions has already consumed the stream and exposes the body as rawBody.
      let raw = req.rawBody ? req.rawBody.toString("utf8") : "";
      if (!req.rawBody) for await (const c of req) { raw += c; if (raw.length > 16_384) break; }
      if (raw.length > 16_384) return send(res, 413, err("error.api.invalid_body"));
      return handleProcess(req, res, raw);
    }
    send(res, 404, err("error.api.not_found"));
  } catch { if (!res.headersSent) send(res, 500, err("error.api.fetch.critical")); else res.destroy(); }
};
const server = http.createServer(handler);

if (process.argv[1] === fileURLToPath(import.meta.url)) server.listen(PORT, () => console.log(`techsave on ${BASE}`));
export { server, handler, parseBody };
