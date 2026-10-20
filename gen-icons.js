// 生成三张纯 PNG 图标（雷达/放大镜风格），用 Node 内置 zlib，不依赖任何外部库。
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { fileURLToPath } from 'node:url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td), 0);
  return Buffer.concat([len, td, crc]);
}

function makeIcon(size) {
  const s = size;
  const rgba = Buffer.alloc(s * s * 4);
  const cx = s / 2, cy = s / 2, maxR = s / 2;
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      const i = (y * s + x) * 4;
      const dx = x - cx + 0.5, dy = y - cy + 0.5;
      const dist = Math.sqrt(dx * dx + dy * dy);
      let r, g, b, a;
      // 深色背景圆盘
      if (dist > maxR) { r = 0; g = 0; b = 0; a = 0; }
      else {
        r = 22; g = 34; b = 51; a = 255;
        // 同心圆（青色）
        for (const rr of [maxR * 0.35, maxR * 0.62, maxR * 0.88]) {
          if (Math.abs(dist - rr) < Math.max(1, s * 0.03)) { r = 45; g = 212; b = 191; a = 255; }
        }
        // 十字准线
        if ((Math.abs(dx) < Math.max(0.6, s * 0.015) || Math.abs(dy) < Math.max(0.6, s * 0.015)) && dist < maxR * 0.88) {
          r = 35; g = 120; b = 150; a = 255;
        }
        // 中心亮核
        if (dist < maxR * 0.12) { r = 255; g = 210; b = 76; a = 255; }
        // 一条雷达扫描臂（右上对角）
        const ang = Math.atan2(dy, dx);
        if (dist < maxR * 0.88 && Math.abs(ang - (-Math.PI / 4)) < 0.12) { r = 255; g = 210; b = 76; a = 255; }
      }
      rgba[i] = r; rgba[i + 1] = g; rgba[i + 2] = b; rgba[i + 3] = a;
    }
  }
  const raw = Buffer.alloc(s * (s * 4 + 1));
  let p = 0;
  for (let y = 0; y < s; y++) { raw[p++] = 0; for (let x = 0; x < s; x++) { const o = (y * s + x) * 4; raw[p++] = rgba[o]; raw[p++] = rgba[o + 1]; raw[p++] = rgba[o + 2]; raw[p++] = rgba[o + 3]; } }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(s, 0); ihdr.writeUInt32BE(s, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  return png;
}

const outDir = path.join(__dirname, 'public', 'icons');
fs.mkdirSync(outDir, { recursive: true });
for (const size of [16, 48, 128]) {
  fs.writeFileSync(path.join(outDir, `icon${size}.png`), makeIcon(size));
  console.log('wrote', `icon${size}.png`);
}
