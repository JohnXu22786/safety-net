// 通用工具：脱敏、展示清洗、TTY 检测

const SECRET_PATTERNS = [
  /\b(?:sk|pk)-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*["']?[^\s"',;]+/gi,
]

/** 对文本中的常见密钥形态进行脱敏，并转义控制字符，用于审计日志 */
export function redact(text) {
  let out = String(text)
  for (const re of SECRET_PATTERNS) out = out.replace(re, '[REDACTED]')
  // 控制字符转义为可见形式，防止日志文件被污染/终端注入
  out = out.replace(/[\x00-\x1f\x7f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
  return out
}

/** 将控制字符转义为可见形式，并截断，用于终端展示 */
export function sanitizeForDisplay(text, maxLen = 600) {
  let out = String(text)
    .replace(/\x1b/g, '<ESC>')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, (c) => `<0x${c.charCodeAt(0).toString(16).toUpperCase()}>`)
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…'
  return out
}

/** 判断流是否为可交互 TTY */
export function isTty(stream) {
  return Boolean(stream && stream.isTTY === true)
}

/** 是否应启用 ANSI 颜色（尊重 NO_COLOR） */
export function useColor(stream, env = process.env) {
  return isTty(stream) && !env.NO_COLOR && !env.BARRICADE_NO_COLOR
}

const ANSI = { red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m', bold: '\x1b[1m', reset: '\x1b[0m' }

/** 简单彩色输出：color 为 false 时原样返回 */
export function paint(text, colorName, enabled) {
  const code = ANSI[colorName]
  return enabled && code ? `${code}${text}${ANSI.reset}` : text
}
