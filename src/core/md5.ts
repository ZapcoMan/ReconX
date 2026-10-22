/**
 * 纯 JS MD5 —— service worker 的 crypto.subtle 不提供 MD5，favicon 指纹需要它。
 * 输入字节数组，输出 32 位小写十六进制摘要。仅用于资产指纹比对（非安全用途）。
 */
export function md5Hex(bytes: Uint8Array): string {
  const ml = bytes.length * 8
  const withOne = bytes.length + 1
  const k = (56 - (withOne % 64) + 64) % 64
  const total = withOne + k + 8
  const msg = new Uint8Array(total)
  msg.set(bytes)
  msg[bytes.length] = 0x80
  const dv = new DataView(msg.buffer)
  dv.setUint32(total - 8, ml >>> 0, true)
  dv.setUint32(total - 4, Math.floor(ml / 4294967296), true)

  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]
  const K = new Int32Array(64)
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  for (let off = 0; off < total; off += 64) {
    const M = new Int32Array(16)
    for (let j = 0; j < 16; j++) M[j] = dv.getInt32(off + j * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F = 0, g = 0
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * i) % 16 }
      F = (F + A + K[i] + M[g]) | 0
      A = D; D = C; C = B
      B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) | 0
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0
  }
  const out = new Uint8Array(16)
  const odv = new DataView(out.buffer)
  odv.setInt32(0, a0, true); odv.setInt32(4, b0, true); odv.setInt32(8, c0, true); odv.setInt32(12, d0, true)
  let hex = ''
  for (let i = 0; i < 16; i++) hex += out[i].toString(16).padStart(2, '0')
  return hex
}
