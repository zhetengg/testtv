// 驰时录 · 映匣 / TVBox type 3 JS 爬虫
// 由 Forward Widget 脚本改写：只保留 搜索 / 详情 / 播放解析
// 约定：全局 req(url, {method, headers, body, timeout}) -> {code, content, headers}

var DS_BUILD = "1791855838435";
var DS_PACKAGE = "com.zyx.cheyong";
var DS_HOST = "http://app2.dsx.ac";
var DS_RSA = {
  p: "fbc7ab9d75533e39971e41b554990a57149ea3d115298d9d17630138a40f315339b7a69c6254dde2ffed520f5ad8c48fd2ef18ffd6c97ea0ca8d7329cf0146d5",
  q: "f36bda059d298c1cf92fae597fcccc5ccb715e3935b485cb4185d20c6c19a3249ca195f4e604ebf1c26f08f75174e72764499d722ee2e10232f16e3aacd9f0fb",
  dp: "7f28e1d0bd6f944eabb6d942c67e208dc85932ad273dfc4aa984141ad228e6257d51f670a6ecebbf78b81828af1e296fe5fd61a7dc87994f85dd189bb5f3941d",
  dq: "6d86a9a2bd0464b6e4a83f9aa596509db02c6268fb712e8236093069c67a029e069bee0d333223b7b3f4a1e42612a3af65c079c756b15eecce5f3369d33c7ce1",
  qi: "88911352f605c0254a3464d8333520eefdd06e5a985c1f88873714dfbb0764e9fa6b8e95e5e24369d6af22fb849a8c491d64f26e2fb566437b2de514838ca50b"
};

/* ---------- 基础工具 ---------- */
function T(v) { return v == null ? "" : String(v).trim(); }

function utf8Bytes(str) {
  var s = unescape(encodeURIComponent(str)), out = [];
  for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}
function utf8Str(bytes) {
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
}
var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64enc(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i += 3) {
    var a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    var n = (a << 16) | ((b || 0) << 8) | (c || 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
      (b === undefined ? "=" : B64[(n >> 6) & 63]) +
      (c === undefined ? "=" : B64[n & 63]);
  }
  return out;
}
function b64dec(str) {
  str = T(str).replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(str) || str.length % 4 === 1) throw new Error("base64 无效");
  var out = [], buf = 0, bits = 0;
  for (var i = 0; i < str.length; i++) {
    buf = (buf << 6) | B64.indexOf(str[i]);
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 255); buf &= (1 << bits) - 1; }
  }
  return out;
}

/* ---------- MD5 ---------- */
function md5(bytes) {
  var K = [], S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21], i;
  for (i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  var len = bytes.length, m = bytes.slice();
  m.push(128);
  while (m.length % 64 !== 56) m.push(0);
  var bitLen = len * 8;
  for (i = 0; i < 8; i++) m.push(i < 4 ? (bitLen >>> (8 * i)) & 255 : Math.floor(len / 536870912) >>> (8 * (i - 4)) & 255);
  var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (var off = 0; off < m.length; off += 64) {
    var M = [];
    for (i = 0; i < 16; i++) M[i] = m[off + i * 4] | (m[off + i * 4 + 1] << 8) | (m[off + i * 4 + 2] << 16) | (m[off + i * 4 + 3] << 24);
    var A = a0, B = b0, C = c0, D = d0;
    for (i = 0; i < 64; i++) {
      var F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      var s = S[(i >> 4) * 4 + (i % 4)];
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  var out = [];
  [a0, b0, c0, d0].forEach(function (v) { for (var j = 0; j < 4; j++) out.push((v >>> (8 * j)) & 255); });
  return out;
}

/* ---------- AES-128-CBC 加密 (PKCS7) ---------- */
var SBOX = (function () {
  var s = [], p = 1, q = 1, x;
  do {
    p = p ^ ((p << 1) & 255) ^ (p & 128 ? 27 : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 255; if (q & 128) q ^= 9;
    x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
    s[p] = (x ^ 99) & 255;
  } while (p !== 1);
  s[0] = 99;
  return s;
})();
function xt(a) { return ((a << 1) ^ (a & 128 ? 27 : 0)) & 255; }
function aesKeyExpand(key) {
  var w = [], i, t;
  for (i = 0; i < 16; i++) w[i] = key[i];
  var rcon = 1;
  for (i = 16; i < 176; i += 4) {
    t = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
    if (i % 16 === 0) {
      t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
      rcon = xt(rcon);
    }
    for (var j = 0; j < 4; j++) w[i + j] = w[i - 16 + j] ^ t[j];
  }
  return w;
}
function aesBlock(blk, w) {
  var s = blk.slice(), r, i;
  for (i = 0; i < 16; i++) s[i] ^= w[i];
  for (r = 1; r <= 10; r++) {
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
    if (r < 10) {
      for (i = 0; i < 16; i += 4) {
        var a = s[i], b = s[i + 1], c = s[i + 2], d = s[i + 3];
        s[i] = xt(a) ^ xt(b) ^ b ^ c ^ d;
        s[i + 1] = a ^ xt(b) ^ xt(c) ^ c ^ d;
        s[i + 2] = a ^ b ^ xt(c) ^ xt(d) ^ d;
        s[i + 3] = xt(a) ^ a ^ b ^ c ^ xt(d);
      }
    }
    for (i = 0; i < 16; i++) s[i] ^= w[r * 16 + i];
  }
  return s;
}
function aesCbcEncrypt(data, key, iv) {
  var pad = 16 - (data.length % 16), m = data.slice(), i;
  for (i = 0; i < pad; i++) m.push(pad);
  var w = aesKeyExpand(key), prev = iv.slice(), out = [];
  for (var off = 0; off < m.length; off += 16) {
    var blk = [];
    for (i = 0; i < 16; i++) blk[i] = m[off + i] ^ prev[i];
    prev = aesBlock(blk, w);
    out = out.concat(prev);
  }
  return out;
}

/* ---------- 请求加密 / 响应 RSA 解密 ---------- */
function dsRequest(method, data) {
  var key = md5(utf8Bytes(DS_BUILD + "^~!@#[-" + DS_PACKAGE)), iv = [];
  for (var i = 0; i < 16; i++) iv.push(Math.floor(Math.random() * 256));
  var input = {};
  Object.keys(data || {}).forEach(function (k) { input[k] = data[k]; });
  input.token = "";
  var body = JSON.stringify({ method: method, data: input, csrf: Date.now() });
  var enc = aesCbcEncrypt(utf8Bytes(body), key, iv);
  return b64enc(iv.concat(enc)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function powmod(base, exp, mod) {
  var out = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) out = out * base % mod;
    exp >>= 1n;
    if (exp > 0n) base = base * base % mod;
  }
  return out;
}
var RSA_STATE;
function dsRSA(value) {
  if (!RSA_STATE) {
    RSA_STATE = {
      p: BigInt("0x" + DS_RSA.p), q: BigInt("0x" + DS_RSA.q),
      dp: BigInt("0x" + DS_RSA.dp), dq: BigInt("0x" + DS_RSA.dq), qi: BigInt("0x" + DS_RSA.qi)
    };
  }
  var r = RSA_STATE, bytes = b64dec(value), size = 128, decoded = [];
  if (!bytes.length || bytes.length % size || bytes.length > 8192) throw new Error("解析响应分块无效");
  for (var off = 0; off < bytes.length; off += size) {
    var hex = "";
    for (var i = off; i < off + size; i++) hex += ("0" + bytes[i].toString(16)).slice(-2);
    var c = BigInt("0x" + hex), a = powmod(c, r.dp, r.p), b = powmod(c, r.dq, r.q);
    var h = (a - b) % r.p;
    if (h < 0n) h += r.p;
    var mm = b + r.q * (r.qi * h % r.p), bh = mm.toString(16);
    while (bh.length < size * 2) bh = "0" + bh;
    var blk = [];
    for (var z = 0; z < bh.length; z += 2) blk.push(parseInt(bh.slice(z, z + 2), 16));
    if (blk.length !== size || blk[0] !== 0 || (blk[1] !== 2 && blk[1] !== 1)) throw new Error("解析响应填充校验失败");
    var end = 2;
    while (end < blk.length && blk[end] !== 0) end++;
    if (end < 10 || end === blk.length) throw new Error("解析响应填充过短");
    for (var n = end + 1; n < blk.length; n++) decoded.push(blk[n]);
  }
  return utf8Str(decoded);
}
function parseJSON(v) {
  if (v && typeof v === "object") return v;
  return JSON.parse(T(v).replace(/^\uFEFF/, ""));
}
function dsReply(value) {
  if (value && typeof value === "object") return value;
  var text = T(value);
  if (/^[\[{]/.test(text)) return parseJSON(text);
  if (/^https?:\/\//i.test(text)) return { code: 200, url: text };
  return parseJSON(dsRSA(text));
}

/* ---------- 网络 ---------- */
var BASE_HEADERS = {
  "User-Agent": "Dart/3.13 (dart:io)",
  "Content-Type": "text/plain",
  version: "2.0.0",
  "version-number": "220",
  "pk-id": DS_PACKAGE,
  "build-time": DS_BUILD,
  platform: "ios",
  "platform-version": "Version 27.2 (Build 24B5110a)"
};
async function dsAPI(method, input) {
  var res = await req(DS_HOST + "/ndsx.php/v7/logs", {
    method: "post",
    headers: BASE_HEADERS,
    body: dsRequest(method, input),
    timeout: 15000
  });
  var data = parseJSON(res.content);
  if (!data || Number(data.code) !== 1) throw new Error("驰时录未返回有效数据");
  return data;
}
function validURL(url) {
  var m = T(url).match(/^https?:\/\/([^/?#]+)/i);
  if (!m || /@|\s/.test(m[1])) return false;
  return !/^(?:localhost|127(?:\.\d{1,3}){1,3}|0\.0\.0\.0|\[::1\])(?::|$)/i.test(m[1]);
}
var BLOCKED_HDR = /^(host|content-length|connection|range|cookie|authorization)$/i;
function toHeaders(value) {
  var out = {};
  if (value && typeof value === "object") {
    Object.keys(value).forEach(function (k) { if (!BLOCKED_HDR.test(k)) out[k] = String(value[k]); });
    return out;
  }
  T(value).split(/\r?\n|\\n/).forEach(function (line) {
    var m = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
    if (m && !BLOCKED_HDR.test(m[1])) out[m[1]] = m[2];
  });
  return out;
}
function playData(obj) {
  if (Array.isArray(obj)) {
    for (var i = 0; i < obj.length; i++) { var e = playData(obj[i]); if (e) return e; }
    return null;
  }
  if (typeof obj === "string") return validURL(obj) ? { url: obj, headers: {} } : null;
  if (!obj || typeof obj !== "object") return null;
  if (obj.code != null && [1, 200].indexOf(Number(obj.code)) < 0) return null;
  if (typeof obj.url === "string" && validURL(obj.url)) return { url: obj.url, headers: toHeaders(obj.headers || obj.header) };
  return obj.data && obj.data !== obj ? playData(obj.data) : null;
}
function parseTargets(src, origin) {
  var apis = [src.parse_api].concat(T(src.extra_parse_api).split(/\r?\n/)), seen = {}, out = [];
  apis.forEach(function (api) {
    api = T(api);
    if (!validURL(api) || seen[api]) return;
    seen[api] = true;
    out.push(api.indexOf("{url}") >= 0 ? api.replace(/\{url\}/g, encodeURIComponent(origin)) : api + encodeURIComponent(origin));
  });
  return out.slice(0, 3);
}

/* ---------- Spider 入口 ---------- */
async function init(cfg) { }

async function home(filter) {
  // 驰时录脚本里只用到搜索和详情接口，这里没有分类，请用搜索
  return JSON.stringify({ class: [], list: [] });
}
async function homeVod() { return JSON.stringify({ list: [] }); }
async function category(tid, pg, filter, extend) {
  return JSON.stringify({ page: 1, pagecount: 1, limit: 0, total: 0, list: [] });
}

async function search(wd, quick, pg) {
  pg = Number(pg) || 1;
  var found = await dsAPI("search", { text: T(wd), pg: pg });
  var items = Array.isArray(found.data) ? found.data : [];
  var list = items.filter(function (it) {
    return it && it.vod_id && !/解说|预告|花絮|片段/.test(T(it.vod_name));
  }).map(function (it) {
    return {
      vod_id: String(it.vod_id),
      vod_name: T(it.vod_name),
      vod_pic: T(it.vod_pic || it.vod_pic_thumb || ""),
      vod_remarks: T(it.vod_state || it.vod_remarks || it.vod_year || "")
    };
  });
  return JSON.stringify({ page: pg, pagecount: Number(found.pagecount) || pg, limit: list.length, total: list.length, list: list });
}

async function detail(id) {
  var info = await dsAPI("video_detail", { id: id, sign_md5: "", apk_path: "", apk_length: 0 });
  var v = info.data && info.data.vod_info;
  if (!v) return JSON.stringify({ list: [] });
  var sources = Array.isArray(v.vod_url_with_player) ? v.vod_url_with_player : [];
  var froms = [], urls = [];
  sources.forEach(function (src) {
    var eps = [];
    T(src.url).split("#").forEach(function (part) {
      var at = part.indexOf("$");
      if (at < 1) return;
      var title = part.slice(0, at).replace(/[$#]/g, " "), origin = part.slice(at + 1);
      var payload = {
        c: T(src.code || src.name), o: origin,
        s: src.parse_secret ? 1 : 0,
        p: src.parse_secret ? [] : parseTargets(src, origin),
        h: toHeaders(src.headers)
      };
      eps.push(title + "$" + encodeURIComponent(JSON.stringify(payload)));
    });
    if (eps.length) {
      froms.push(T(src.name || src.code || "线路").replace(/[$#]/g, " "));
      urls.push(eps.join("#"));
    }
  });
  return JSON.stringify({
    list: [{
      vod_id: String(v.vod_id || id),
      vod_name: T(v.vod_name),
      vod_pic: T(v.vod_pic || ""),
      vod_year: T(v.vod_year || ""),
      vod_area: T(v.vod_area || ""),
      vod_actor: T(v.vod_actor || ""),
      vod_director: T(v.vod_director || ""),
      vod_content: T(v.vod_content || v.vod_blurb || ""),
      vod_play_from: froms.join("$$$"),
      vod_play_url: urls.join("$$$")
    }]
  });
}

async function play(flag, id, flags) {
  var p;
  try { p = JSON.parse(decodeURIComponent(id)); } catch (e) { return JSON.stringify({ parse: 0, url: "" }); }
  var result = null, i;
  if (p.s) {
    try {
      var sec = await dsAPI("secret_parse_api_url", { url: p.o, player_code: p.c });
      result = playData(sec.data);
    } catch (e) { }
  } else {
    for (i = 0; i < p.p.length && !result; i++) {
      try {
        var r = await req(p.p[i], { method: "get", headers: { "User-Agent": "Dart/3.13 (dart:io)" }, timeout: 15000 });
        result = playData(dsReply(r.content));
      } catch (e) { }
    }
    if (!result && /\.(?:m3u8|mp4|mkv|mov)(?:[?#]|$)/i.test(p.o)) result = { url: p.o, headers: {} };
  }
  if (!result) return JSON.stringify({ parse: 0, url: "" });
  var header = {};
  Object.keys(p.h || {}).forEach(function (k) { header[k] = p.h[k]; });
  Object.keys(result.headers || {}).forEach(function (k) { header[k] = result.headers[k]; });
  return JSON.stringify({ parse: 0, url: result.url, header: header });
}

var spider = { init: init, home: home, homeVod: homeVod, category: category, detail: detail, play: play, search: search };
export function __jsEvalReturn() { return spider; }
export default spider;
