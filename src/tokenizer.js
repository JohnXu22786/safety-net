// POSIX 风格 shell 词法分析器。
// 职责：把命令字符串切成词（word）、操作符（operator）、heredoc 正文与命令替换，
// 供分析器做语义级判断。本模块不做任何执行。
// 实现要点：词用片段数组累积（线性复杂度），括号附着用标记位判断，支持 ANSI-C 引号。

export const MAX_INPUT_LEN = 131072

const BOUNDARY_OPS = new Set(['&&', '||', ';;', ';', '&', '|', '|&'])
const OPERATOR_ORDER = ['<<<', '<<-', '<<', '>>', '>|', '>&', '<&', '&&', '||', ';;', '|&', '>', '<', ';', '&', '|', '(', ')']

/**
 * 分词。返回 { ok, tokens, error? }
 * token 类型:
 *   word        普通词（引号已去除，内容保持字面）
 *   operator    操作符（见 OPERATOR_ORDER；换行等价于 ';'）
 *   heredoc     heredoc 正文 { value, delimiter, quoted, indent }
 *   substitution 命令替换内容 { value }（$(...) 或反引号内部）
 */
export function tokenize(input, { maxLen = MAX_INPUT_LEN } = {}) {
  if (typeof input !== 'string') return { ok: false, error: 'bad-input', tokens: [] }
  if (input.length > maxLen) return { ok: false, error: 'input-too-long', tokens: [] }

  const tokens = []
  let i = 0
  let wordParts = [] // 词片段（避免字符串逐字符拼接的二次方复杂度）
  let wordQuoted = false
  let wordHasOpenParen = false // 词内是否含 '('（决定 ')' 是否附着）
  let heredocPending = null // { indent: boolean }，等待定界符词
  let heredocSkip = null // { from, to }：正文区间，主循环落在区间内时直接跳过

  const word = () => wordParts.join('')

  const flushWord = () => {
    if (wordParts.length === 0) return false
    tokens.push({ type: 'word', value: wordParts.join('') })
    if (heredocPending) {
      // 捕获 heredoc 正文：定界符词刚被推出，正文从下一行开始
      captureHeredoc(heredocPending.indent, wordParts.join(''), wordQuoted)
      heredocPending = null
      wordParts = []
      wordQuoted = false
      wordHasOpenParen = false
      return true // 本次 flush 触发了 heredoc 捕获
    }
    wordParts = []
    wordQuoted = false
    wordHasOpenParen = false
    return false
  }

  const appendWord = (part) => {
    wordParts.push(part)
    if (!wordHasOpenParen && typeof part === 'string' && part.includes('(')) wordHasOpenParen = true
  }

  const captureHeredoc = (indent, delimiter, quoted) => {
    let j = i
    while (j < input.length && (input[j] === ' ' || input[j] === '\t')) j++
    if (j >= input.length || input[j] !== '\n') {
      // 定界符后同一行还有其他内容（如 <<EOF > f 或 <<EOF && echo）：
      // 正文从下一个换行开始，行内内容仍属于本命令（endOfLine=false）
      const nl = input.indexOf('\n', j)
      if (nl === -1 || nl >= input.length - 1) {
        tokens.push({ type: 'heredoc', value: '', delimiter, quoted, indent, endOfLine: false })
        return
      }
      j = nl
      tokens.push({ type: 'heredoc', value: '', delimiter, quoted, indent, endOfLine: false })
      j++
      const bodyStart = j
      while (j <= input.length) {
        let eol = input.indexOf('\n', j)
        if (eol === -1) eol = input.length
        let line = input.slice(j, eol)
        if (indent && /^\t+/.test(line)) line = line.replace(/^\t+/, '')
        if (line === delimiter) {
          let body = input.slice(bodyStart, j)
          if (body.endsWith('\n')) body = body.slice(0, -1)
          if (indent) body = body.split('\n').map((l) => l.replace(/^\t+/, '')).join('\n')
          tokens[tokens.length - 1].value = body
          heredocSkip = { from: bodyStart, to: eol < input.length ? eol + 1 : input.length }
          return
        }
        if (eol === input.length) {
          tokens[tokens.length - 1].value = input.slice(bodyStart, input.length)
          heredocSkip = { from: bodyStart, to: input.length }
          return
        }
        j = eol + 1
      }
      return
    }
    j++ // 跳过换行
    const bodyStart = j
    while (j <= input.length) {
      let eol = input.indexOf('\n', j)
      if (eol === -1) eol = input.length
      let line = input.slice(j, eol)
      if (indent && /^\t+/.test(line)) line = line.replace(/^\t+/, '')
      if (line === delimiter) {
        let body = input.slice(bodyStart, j)
        if (body.endsWith('\n')) body = body.slice(0, -1)
        if (indent) body = body.split('\n').map((l) => l.replace(/^\t+/, '')).join('\n')
        tokens.push({ type: 'heredoc', value: body, delimiter, quoted, indent, endOfLine: true })
        heredocSkip = { from: bodyStart, to: eol < input.length ? eol + 1 : input.length }
        return
      }
      if (eol === input.length) {
        tokens.push({ type: 'heredoc', value: input.slice(bodyStart, input.length), delimiter, quoted, indent, endOfLine: true })
        heredocSkip = { from: bodyStart, to: input.length }
        return
      }
      j = eol + 1
    }
  }

  /** 提取 $(...) 或反引号内容，返回 { end, inner }，未闭合时 end 指向末尾 */
  const extractParen = (start) => {
    let depth = 1
    let k = start
    let q = null
    while (k < input.length) {
      const c = input[k]
      if (q === "'") {
        if (c === "'") q = null
      } else if (q === '"') {
        if (c === '\\') k++
        else if (c === '"') q = null
      } else if (c === "'") q = "'"
      else if (c === '"') q = '"'
      else if (c === '\\') k++
      else if (c === '(') depth++
      else if (c === ')') {
        depth--
        if (depth === 0) return { end: k, inner: input.slice(start, k) }
      }
      k++
    }
    return { end: input.length, inner: input.slice(start, input.length) }
  }

  const extractBacktick = (start) => {
    let k = start
    while (k < input.length) {
      if (input[k] === '\\') { k += 2; continue }
      if (input[k] === '`') return { end: k, inner: input.slice(start, k) }
      k++
    }
    return { end: input.length, inner: input.slice(start, input.length) }
  }

  /** ANSI-C 引号解码：\a \b \e \f \n \r \t \v \\ \' \" \? \xHH \uHHHH \NNN(八进制) */
  const decodeAnsiC = (text) => {
    let out = ''
    let k = 0
    while (k < text.length) {
      const c = text[k]
      if (c !== '\\') { out += c; k++; continue }
      const d = text[k + 1]
      const simple = { a: '\x07', b: '\x08', e: '\x1b', f: '\x0c', n: '\n', r: '\r', t: '\t', v: '\x0b', '\\': '\\', "'": "'", '"': '"', '?': '?' }
      if (d !== undefined && simple[d] !== undefined) { out += simple[d]; k += 2; continue }
      if (d === 'x' || d === 'X') {
        const m = /^[0-9a-fA-F]{1,2}/.exec(text.slice(k + 2))
        if (m) { out += String.fromCharCode(parseInt(m[0], 16)); k += 2 + m[0].length; continue }
      }
      if (d === 'u') {
        const m = /^[0-9a-fA-F]{1,4}/.exec(text.slice(k + 2))
        if (m) { out += String.fromCharCode(parseInt(m[0], 16)); k += 2 + m[0].length; continue }
      }
      if (d !== undefined && /^[0-7]$/.test(d)) {
        const m = /^[0-7]{1,3}/.exec(text.slice(k + 1))
        if (m) { out += String.fromCharCode(parseInt(m[0], 8)); k += 1 + m[0].length; continue }
      }
      // 未知转义：保留原样
      out += c
      k++
    }
    return out
  }

  while (i < input.length) {
    const c = input[i]

    // heredoc 正文区间整体跳过（不含定界符所在行之前的行内内容）
    if (heredocSkip && i >= heredocSkip.from && i < heredocSkip.to) { i = heredocSkip.to; continue }

    // 注释：词起始处的 # 直到行尾
    if (c === '#' && wordParts.length === 0) {
      while (i < input.length && input[i] !== '\n') i++
      continue
    }

    // 操作符优先（即使正在组词也会切分，如 a&&b / 2>&1）。
    // 例外:
    //   - '(' 在词非空时附着为词的一部分（如 f()、echo a(b)）；
    //   - ')' 仅当词内已含 '(' 时附着（如 f()），否则是收尾操作符（如 (rm -rf /)）
    let op = null
    for (const candidate of OPERATOR_ORDER) {
      if (candidate === '(' && wordParts.length > 0) continue
      if (candidate === ')' && wordParts.length > 0 && wordHasOpenParen) continue
      if (input.startsWith(candidate, i)) { op = candidate; break }
    }
    if (op) {
      flushWord()
      tokens.push({ type: 'operator', value: op })
      if (op === '<<' || op === '<<-') heredocPending = { indent: op === '<<-' }
      i += op.length
      continue
    }

    // 空白与换行（换行是命令分隔符，等价于 ';'）
    if (c === ' ' || c === '\t') {
      flushWord()
      i++
      continue
    }
    if (c === '\n') {
      const captured = flushWord()
      if (tokens.length > 0 && !captured) tokens.push({ type: 'operator', value: ';' })
      i++
      continue
    }

    // 单引号：全部字面
    if (c === "'") {
      const end = input.indexOf("'", i + 1)
      if (end === -1) return { ok: false, error: 'unterminated-quote', tokens }
      appendWord(input.slice(i + 1, end))
      wordQuoted = true
      i = end + 1
      continue
    }

    // ANSI-C 引号 $'...'：转义序列解码后作为字面内容
    if (c === '$' && input[i + 1] === "'") {
      let k = i + 2
      let closed = false
      while (k < input.length) {
        if (input[k] === '\\') { k += 2; continue }
        if (input[k] === "'") { closed = true; break }
        k++
      }
      if (!closed) return { ok: false, error: 'unterminated-quote', tokens }
      appendWord(decodeAnsiC(input.slice(i + 2, k)))
      wordQuoted = true
      i = k + 1
      continue
    }

    // 双引号：转义仅对 $ ` " \ 生效；引号内的 $(...) 与反引号同样是命令替换
    if (c === '"') {
      let k = i + 1
      let closed = false
      while (k < input.length) {
        const d = input[k]
        if (d === '\\' && k + 1 < input.length && '$`"\\'.includes(input[k + 1])) { appendWord(input[k + 1]); k += 2; continue }
        if (d === '\\') { appendWord('\\'); k += 1; continue }
        if (d === '"') { i = k + 1; wordQuoted = true; closed = true; break }
        if (d === '$' && input[k + 1] === '(' && input[k + 2] === '(') {
          // 算术展开 $((...)): 字面量
          let depth = 2
          let kk = k + 3
          while (kk < input.length && depth > 0) {
            if (input[kk] === '(') depth++
            else if (input[kk] === ')') depth--
            kk++
          }
          appendWord(input.slice(k, kk))
          k = kk
          continue
        }
        if (d === '$' && input[k + 1] === '(') {
          const r = extractParen(k + 2)
          appendWord(input.slice(k, r.end + 1))
          tokens.push({ type: 'substitution', value: r.inner })
          k = r.end + 1
          continue
        }
        if (d === '`') {
          const r = extractBacktick(k + 1)
          appendWord(input.slice(k, r.end + 1))
          tokens.push({ type: 'substitution', value: r.inner })
          k = r.end + 1
          continue
        }
        appendWord(d)
        k++
      }
      if (!closed) return { ok: false, error: 'unterminated-quote', tokens }
      continue
    }

    // 反斜杠转义（引号外）
    if (c === '\\') {
      if (i + 1 < input.length && input[i + 1] === '\n') { i += 2; continue } // 续行
      if (i + 1 < input.length) { appendWord(input[i + 1]); i += 2; continue }
      appendWord('\\')
      i++
      continue
    }

    // 命令替换 $(...) 与反引号
    if (c === '$' && input[i + 1] === '(' && input[i + 2] === '(') {
      // 算术展开 $((...)): 视为字面量, 不产生 substitution
      let depth = 2
      let k = i + 3
      while (k < input.length && depth > 0) {
        if (input[k] === '(') depth++
        else if (input[k] === ')') depth--
        k++
      }
      appendWord(input.slice(i, k))
      i = k
      continue
    }
    if (c === '$' && input[i + 1] === '(') {
      const r = extractParen(i + 2)
      appendWord(input.slice(i, r.end + 1))
      tokens.push({ type: 'substitution', value: r.inner })
      i = r.end + 1
      continue
    }
    if (c === '$' && input[i + 1] === '{') {
      let depth = 1
      let k = i + 2
      while (k < input.length && depth > 0) {
        if (input[k] === '{') depth++
        else if (input[k] === '}') depth--
        k++
      }
      appendWord(input.slice(i, k))
      i = k
      continue
    }
    if (c === '`') {
      const r = extractBacktick(i + 1)
      appendWord(input.slice(i, r.end + 1))
      tokens.push({ type: 'substitution', value: r.inner })
      i = r.end + 1
      continue
    }

    // 普通字符
    appendWord(c)
    i++
  }

  flushWord()
  return { ok: true, tokens }
}
