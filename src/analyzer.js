// 命令分析引擎：把 token 流组织为命令段，逐段做语义分析。
// 分析按 POSIX 路径语义进行（对命令文本的静态分析，与运行平台无关）。

import { posix as path } from 'node:path'
import { tokenize } from './tokenizer.js'
import { Policy } from './policy.js'
import { combineMatches, Verdict } from './verdict.js'
import { findRule, mkMatch, LEVEL_ORDER } from './rules.js'

export const MAX_INPUT_LEN = 131072
export const MAX_DEPTH = 8

const BOUNDARY_OPS = new Set(['&&', '||', ';', '&', '|', '|&', ';;'])
const REDIRECT_OPS = new Set(['>', '>>', '>|', '>&', '<&', '<', '<<', '<<-', '<<<'])
const FUNC_DEF_RE = /^[A-Za-z_][A-Za-z0-9_]*\(\)\{?$/
const ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/
const FORK_BOMB_RE = /:\(\)\s*\{/
const WINDOWS_PATH_RE = /^[A-Za-z]:[\\/]/
const GLOB_CHARS_RE = /[*?[]/
const IFS_RE = /\$\{?IFS\}?/
const TEMP_PATHS = ['/tmp', '/var/tmp']

const COMPOUND_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', 'for', 'in', 'case', 'esac'])

const SHELLS = new Set(['bash', 'sh', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'ash', 'mksh'])
const INTERP_CMDS = new Set(['python', 'python2', 'python3', 'node', 'nodejs', 'deno', 'ruby', 'perl', 'perl5', 'php'])
const POWER_CMDS = new Set(['powershell', 'pwsh', 'cmd'])
const SHUTDOWN_CMDS = new Set(['shutdown', 'halt', 'poweroff'])
const NETWORK_SUBS = new Set(['clone', 'fetch', 'pull', 'push', 'ls-remote', 'submodule'])
const SSH_ENV_KEYS = ['GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_SSH_VARIANT']

/** 通用包装命令表：flags 不带值，values 带一个值 */
const WRAPPERS = {
  sudo: { values: ['-u', '-g', '-p', '-C', '-D', '-r', '-t'], flags: ['-H', '-E', '-n', '-S', '-v', '-k', '-l', '-i', '-s', '-b', '-P', '-A'] },
  doas: { values: ['-u'], flags: ['-n', '-s'] },
  env: { values: ['-C', '-u', '-U'], flags: ['-i', '-0'], payloadFlag: '-S', payloadLong: '--split-string' },
  command: { values: [], flags: ['-v', '-V', '-p'] },
  builtin: { values: [], flags: [] },
  nohup: { values: [], flags: [] },
  nice: { values: ['-n'], flags: [] },
  setsid: { values: [], flags: ['-f', '-w', '-c'] },
  stdbuf: { values: ['-i', '-o', '-e'], flags: [] },
  ionice: { values: ['-c', '-n', '-p', '-t'], flags: [] },
  taskset: { values: ['-c', '-p'], flags: [], posValue: true },
  chrt: { values: ['-p'], flags: [], posValue: true },
  exec: { values: [], flags: [] },
  time: { values: ['-p'], flags: [] },
  timeout: { values: ['-k', '-s', '--signal', '--kill-after'], flags: ['-v'], posValue: true },
  eatmydata: { values: [], flags: [] },
  faketime: { values: ['-f', '-i', '-d'], flags: [] },
}

/** git 子命令的危险形态表 */
const GIT_SUBS = {
  reset: { longs: { '--hard': 'git/reset-hard', '--merge': 'git/reset-hard' } },
  clean: {
    shorts: { f: 'git/clean-force' },
    longs: { '--force': 'git/clean-force' },
    dryShorts: ['n'],
    dryLongs: ['--dry-run'],
  },
  push: {
    shorts: { f: 'git/push-force', d: 'git/push-delete' },
    longs: {
      '--force': 'git/push-force',
      '--force-with-lease': 'git/push-force',
      '--delete': 'git/push-delete',
      '--mirror': 'git/push-force',
    },
    dryShorts: ['n'],
    dryLongs: ['--dry-run'],
  },
  checkout: { shorts: { f: 'git/checkout-force' }, longs: { '--force': 'git/checkout-force' } },
  switch: { shorts: { f: 'git/switch-force' }, longs: { '--force': 'git/switch-force', '--discard-changes': 'git/switch-force' } },
  branch: { shorts: { D: 'git/branch-delete-force' }, longs: {}, pair: null },
  tag: { shorts: { d: 'git/tag-delete', D: 'git/tag-delete' }, longs: { '--delete': 'git/tag-delete' } },
  stash: { sub: { drop: 'git/stash-drop', clear: 'git/stash-clear' } },
  restore: { rule: 'git/restore-worktree', stagedOnly: true },
  fetch: { shorts: { f: 'git/fetch-force' }, longs: { '--force': 'git/fetch-force' } },
}

const DANGEROUS_CODE_RE = /(?:rm\s+-[a-zA-Z]*r|shutil\.rmtree|os\.system|os\.remove\b|subprocess|child_process|execSync|execFileSync|spawnSync|FileUtils\.rm_rf|remove_entry|system\s*\(|\bunlink\b|\bremove\s*\()/i

const SAFE_DEV_TARGETS = new Set(['null', 'zero', 'random', 'urandom', 'tty', 'stdout', 'stderr', 'stdin'])
const BLOCK_DEV_RE = /\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|mapper|md|loop|disk|dm-)/

const RAW_PATTERNS = [
  { rule: 'fs/rm-root', re: /\brm\s+[^\n;&|]{0,256}\s+\/(?:\s|$|[;&|])/ },
  { rule: 'fs/rm-home', re: /\brm\s+[^\n;&|]{0,256}\s+(?:~|\$\{?HOME\}?)(?:\s|$|[;&|])/ },
  { rule: 'git/reset-hard', re: /\bgit\s+(?:-\S{0,32}\s+){0,8}reset\s+--hard\b/ },
  { rule: 'git/clean-force', re: /\bgit\s+(?:-\S{0,32}\s+){0,8}clean\s+-\S{0,32}f\S{0,32}/ },
  { rule: 'git/push-force', re: /\bgit\s+(?:-\S{0,32}\s+){0,8}push\s+(?:[^\s;&|]{0,32} ){0,16}(?:-f\b|--force(?:-with-lease)?\b)/ },
  { rule: 'fs/dd-device', re: /\bdd\b[^\n;&|]{0,256}\bof=\/dev\/(?!null\b|zero\b|random\b|urandom\b|tty\b|stdout\b|stderr\b|stdin\b)/ },
  { rule: 'fs/mkfs-device', re: /\bmkfs(?:\.\w+)?\s+[^\n;&|]{0,256}\/dev\// },
  { rule: 'sys/powershell-remove', re: /Remove-Item[\s\S]{0,512}?(?:Recurse|R\b)[\s\S]{0,512}?(?:Force|F\b)/i },
]
const RAW_EXEMPT_FIRST = new Set(['echo', 'printf', 'rg', 'grep', 'cat', 'head', 'tail', 'less', 'man', 'which', 'type'])
const RAW_EXEMPT_PAIR = new Set(['command -v'])
const RAW_BOUNDARY_RE = /[;&|\n]/

/**
 * 分析一条命令，返回 Verdict。
 * @param {string} command 命令文本
 * @param {{policy?: Policy, cwd?: string, home?: string, env?: object, maxDepth?: number, maxInput?: number}} opts
 */
export function analyzeCommand(command, opts = {}) {
  let policy = opts.policy instanceof Policy ? opts.policy : Policy.fromObject(opts.policy ?? {})
  if (opts.level) policy = policy.withLevel(opts.level)

  const ctx = {
    policy,
    cwd: opts.cwd ?? '/',
    workspace: opts.cwd ?? '/',
    home: opts.home ?? '/home',
    env: opts.env ?? process.env,
    maxDepth: opts.maxDepth ?? MAX_DEPTH,
    maxInput: opts.maxInput ?? MAX_INPUT_LEN,
    warnings: [],
    heredocs: new Map(),
    exportedEnv: {},
  }

  const cmd = typeof command === 'string' ? command : ''
  if (cmd.trim() === '' && typeof command === 'string') return Verdict.allow(cmd)
  // 非字符串输入：按不可解析处理（failClosed 时要求确认）
  if (typeof command !== 'string') {
    const raw = rawScan('', ctx)
    const extra = ['输入不是字符串，视为不可解析命令']
    const failClosed = policy.failClosed || policy.level === 'vigilant'
    if (failClosed) {
      extra.push('failClosed 开启：无法解析的命令需要人工确认')
      raw.matches.push(mkMatch(findRule('shell/unparseable'), '命令无法解析'))
    }
    return combineMatches('', raw.matches, [...ctx.warnings, ...raw.warnings, ...extra], policy)
  }
  if (cmd.length > ctx.maxInput) {
    ctx.warnings.push(`输入长度超过上限 ${ctx.maxInput}，仅执行粗粒度扫描`)
    const raw = rawScan(cmd, ctx)
    const extra = [...ctx.warnings, ...raw.warnings]
    // 超长输入同不可解析输入一样受 failClosed 约束
    const failClosed = policy.failClosed || policy.level === 'vigilant'
    if (failClosed) {
      extra.push('failClosed 开启：超长命令需要人工确认')
      raw.matches.push(mkMatch(findRule('shell/unparseable'), '输入超长，命令无法完整解析'))
    }
    return combineMatches(cmd, raw.matches, extra, policy)
  }

  const res = tokenize(cmd, { maxLen: ctx.maxInput })
  if (!res.ok) {
    const raw = rawScan(cmd, ctx)
    const extra = [`命令无法解析（${res.error}），执行粗粒度扫描`]
    // vigilant 等级默认开启 failClosed 语义
    const failClosed = policy.failClosed || policy.level === 'vigilant'
    if (failClosed) {
      extra.push('failClosed 开启：无法解析的命令需要人工确认')
      raw.matches.push(mkMatch(findRule('shell/unparseable'), '命令无法解析'))
    }
    return combineMatches(cmd, raw.matches, [...ctx.warnings, ...raw.warnings, ...extra], policy)
  }

  const matches = []
  if (FORK_BOMB_RE.test(cmd)) {
    matches.push(mkMatch(findRule('shell/fork-bomb'), '检测到 fork 炸弹'))
  }
  const segments = buildSegments(res.tokens)
  // allowlist 仅对第一个命令段生效，其余段照常分析（防 git status && rm -rf / 绕过）
  const firstCmdIdx = segments.findIndex((s) => s.type === 'cmd')
  if (firstCmdIdx !== -1) {
    const headText = segments[firstCmdIdx].words.filter((t) => t.type === 'word').map((t) => t.value).join(' ')
    if (policy.checkAllowlist(headText)) {
      // 被放行段自身的 heredoc 写盘记录仍要登记（供后续 bash <path> 回放）
      for (const h of segments[firstCmdIdx].heredocs) {
        if (h.target) ctx.heredocs.set(h.target, h.value)
      }
      const rest = segments.slice(firstCmdIdx + 1)
      // 首段与下一段之间若为管道，管道对检查仍需覆盖该边界
      if (rest.length > 0 && (rest[0].sep === '|' || rest[0].sep === '|&')) {
        const pair = checkPipePair(segments[firstCmdIdx], rest[0])
        if (pair) matches.push(pair)
        const rightCmd = stripWrappers(rest[0].words)[0]?.value
        if (SHELLS.has(rightCmd) && segments[firstCmdIdx].heredocs.length > 0) {
          for (const h of segments[firstCmdIdx].heredocs) recurseCommand(h.value, ctx, matches, '（管道左侧 heredoc 内容）')
        }
      }
      analyzeList(rest, ctx, 0, matches)
      return combineMatches(cmd, matches, ctx.warnings, policy)
    }
  }
  analyzeList(segments, ctx, 0, matches)
  return combineMatches(cmd, matches, ctx.warnings, policy)
}

/** 把 token 流组织为命令段列表。段类型: cmd {words, redirects, heredocs, sep} | sub {segments}
 *  sep: 本段之前的连接操作符（用于管道/子 shell 语义） */
export function buildSegments(tokens) {
  const root = { type: 'list', segments: [] }
  let list = root
  const stack = []
  let seg = null
  let pendingRedirect = null
  let lastGTarget = null
  let pendingSep = null

  const ensureSeg = () => {
    if (!seg) {
      seg = { type: 'cmd', words: [], redirects: [], heredocs: [], sep: pendingSep }
      pendingSep = null
      list.segments.push(seg)
    }
    return seg
  }
  const closeSeg = () => { seg = null }

  for (const t of tokens) {
    if (t.type === 'operator') {
      const v = t.value
      if (BOUNDARY_OPS.has(v)) {
        closeSeg()
        pendingRedirect = null
        lastGTarget = null
        pendingSep = v
        continue
      }
      if (v === '(') {
        closeSeg()
        pendingRedirect = null
        lastGTarget = null
        pendingSep = null
        const sub = { type: 'sub', segments: [] }
        list.segments.push(sub)
        stack.push(list)
        list = sub
        continue
      }
      if (v === ')') {
        closeSeg()
        pendingRedirect = null
        lastGTarget = null
        list = stack.pop() ?? root
        continue
      }
      if (REDIRECT_OPS.has(v)) {
        const s = ensureSeg()
        if (v === '<<' || v === '<<-') { pendingRedirect = { op: 'heredoc' } }
        else {
          // 每种重定向都是独立条目（2>&1 不会覆盖前面 > 的目标）
          s.redirects.push({ op: v, target: null })
          pendingRedirect = { op: 'target' }
        }
        continue
      }
      continue
    }
    if (t.type === 'heredoc') {
      const s = ensureSeg()
      s.heredocs.push({ value: t.value, delimiter: t.delimiter, quoted: t.quoted, target: pendingRedirect?.op === 'heredoc' ? lastGTarget : null })
      pendingRedirect = null
      // 定界符在行尾（endOfLine）时命令结束，后续内容属于新命令；
      // 行内还有内容（如 <<EOF > f）时命令继续，由后续边界操作符切分
      if (t.endOfLine !== false) closeSeg()
      continue
    }
    if (pendingRedirect) {
      if (pendingRedirect.op === 'heredoc') {
        // 定界符词/替换：保留 pending，等待随后的 heredoc token 消费
        continue
      }
      if (t.type === 'substitution') {
        // 重定向目标位置上的命令替换同样会被执行（echo hi >$(rm -rf /)）
        const s = ensureSeg()
        s.words.push(t)
        pendingRedirect = null
        continue
      }
      if (t.type === 'word') {
        const s = ensureSeg()
        const rd = s.redirects[s.redirects.length - 1]
        if (rd && rd.target === null) rd.target = t.value
        if (rd && (rd.op === '>' || rd.op === '>>')) lastGTarget = t.value
        pendingRedirect = null
        continue
      }
      pendingRedirect = null
      continue
    }
    const s = ensureSeg()
    s.words.push(t)
  }
  // 后处理：heredoc 目标为空的段，若同段存在 '>' 重定向目标则补记
  // （cat <<EOF > /tmp/evil 形式：正文经 stdout 重定向写盘）
  const attachHeredocTargets = (list) => {
    for (const sg of list.segments) {
      if (sg.type === 'sub') { attachHeredocTargets(sg); continue }
      for (const h of sg.heredocs) {
        if (h.target !== null) continue
        for (let j = sg.redirects.length - 1; j >= 0; j--) {
          const rd = sg.redirects[j]
          if ((rd.op === '>' || rd.op === '>>' || rd.op === '>|') && rd.target) { h.target = rd.target; break }
        }
      }
    }
  }
  attachHeredocTargets(root)
  return root.segments
}

/** 逐段分析：管道链/子 shell 的 cwd 隔离、管道对检查 */
function analyzeList(segments, ctx, depth, matches) {
  let prev = null
  let i = 0
  while (i < segments.length) {
    const seg = segments[i]
    if (seg.type === 'sub') {
      // 子 shell：内部 cd/export 不影响外部
      const subCtx = { ...ctx, exportedEnv: { ...ctx.exportedEnv } }
      analyzeList(seg.segments, subCtx, depth, matches)
      for (const [k, v] of subCtx.heredocs) ctx.heredocs.set(k, v)
      prev = null
      i++
      continue
    }
    // 管道链：各元素在子 shell 中运行，cwd 互相隔离且不外泄
    const chain = [seg]
    while (i + 1 < segments.length && (segments[i + 1].sep === '|' || segments[i + 1].sep === '|&')) {
      chain.push(segments[i + 1])
      i++
    }
    if (chain.length > 1) {
      for (let j = 0; j < chain.length; j++) {
        if (j > 0) {
          const pair = checkPipePair(chain[j - 1], chain[j])
          if (pair) addMatch(matches, pair)
          // 左段携带 heredoc 且右段是 shell → 正文会被执行
          const rightCmd = stripWrappers(chain[j].words)[0]?.value
          if (SHELLS.has(rightCmd) && chain[j - 1].heredocs.length > 0) {
            for (const h of chain[j - 1].heredocs) recurseCommand(h.value, ctx, matches, '（管道左侧 heredoc 内容）')
          }
        }
        const chainCtx = { ...ctx, exportedEnv: { ...ctx.exportedEnv } }
        analyzeSegment(chain[j], chainCtx, depth, matches)
        for (const [k, v] of chainCtx.heredocs) ctx.heredocs.set(k, v)
      }
      prev = chain[chain.length - 1]
      i++
      continue
    }
    if (prev) {
      const pair = checkPipePair(prev, seg)
      if (pair) addMatch(matches, pair)
    }
    analyzeSegment(seg, ctx, depth, matches)
    prev = seg
    i++
  }
}

/** 检查相邻两段是否为“下载 → 管道 → shell”形态 */
function checkPipePair(prev, cur) {
  const left = stripWrappers(prev.words)
  const right = stripWrappers(cur.words)
  if (left.length === 0 || right.length === 0) return null
  const l = left[0]?.value
  const r = right[0]?.value
  if ((l === 'curl' || l === 'wget') && SHELLS.has(r)) {
    return mkMatch(findRule('shell/curl-pipe-sh'), `左侧 ${l} 下载的内容将直接交给 ${r} 执行`)
  }
  return null
}

/** 剥离赋值与通用包装命令，返回剩余词列表（不递归 -c 负载） */
function stripWrappers(words) {
  let idx = 0
  const isWord = (t) => t && t.type === 'word'
  while (idx < words.length && isWord(words[idx])) {
    const v = words[idx].value
    if (ASSIGN_RE.test(v)) { idx++; continue }
    if (v === 'export') { idx++; continue }
    const spec = WRAPPERS[v]
    if (!spec) break
    idx++
    if (spec.posValue && isWord(words[idx]) && /^\d+(\.\d+)?[smhd]?$/.test(words[idx].value)) idx++
    while (idx < words.length && isWord(words[idx])) {
      const o = words[idx].value
      if (o === '--') { idx++; break }
      if (!o.startsWith('-') || o === '-') break
      if (spec.values.includes(o)) { idx += 2; continue }
      idx++
    }
  }
  return words.slice(idx)
}

/** 分析单个命令段 */
function analyzeSegment(seg, ctx, depth, matches) {
  if (ctx.maxDepth <= 0 || depth >= ctx.maxDepth) {
    addMatch(matches, mkMatch(findRule('shell/depth-limit'), `嵌套深度超过 ${ctx.maxDepth} 层，停止深入分析`))
    return
  }

  // heredoc 写盘记录（供后续 bash <path> 回放分析）
  for (const h of seg.heredocs) {
    if (h.target) ctx.heredocs.set(h.target, h.value)
  }
  // 重定向到 .git 内部 → 元数据保护
  for (const rd of seg.redirects) {
    if ((rd.op === '>' || rd.op === '>>' || rd.op === '>|') && rd.target && containsGitMeta(rd.target)) {
      addMatch(matches, mkMatch(findRule('fs/rm-git'), `重定向目标 ${rd.target} 位于 .git 内部`))
    }
  }
  // 命令替换内容递归分析
  for (const t of seg.words) {
    if (t.type !== 'substitution') continue
    recurseCommand(t.value, ctx, matches, '（位于命令替换内）')
  }

  const words = seg.words.filter((t) => t.type === 'word')
  if (words.length === 0) return

  // 段内赋值（供 GIT_SSH 检查）；export 的变量对后续段可见
  const assignments = {}
  let idx = 0
  let exported = false
  while (idx < words.length && ASSIGN_RE.test(words[idx].value)) {
    const eq = words[idx].value.indexOf('=')
    assignments[words[idx].value.slice(0, eq)] = words[idx].value.slice(eq + 1)
    idx++
  }
  if (words[idx]?.value === 'export') {
    exported = true
    idx++
    while (idx < words.length && ASSIGN_RE.test(words[idx].value)) {
      const eq = words[idx].value.indexOf('=')
      assignments[words[idx].value.slice(0, eq)] = words[idx].value.slice(eq + 1)
      idx++
    }
  }
  if (exported) {
    for (const [k, v] of Object.entries(assignments)) ctx.exportedEnv[k] = v
  }

  const first = words[idx]
  if (!first) return // 只有赋值/重定向等
  const cmd = first.value

  // unset：删除已导出的变量（export 状态的撤销）
  if (cmd === 'unset') {
    for (const w of words.slice(idx + 1)) delete ctx.exportedEnv[w.value]
    return
  }

  // cd / pushd / popd 影响后续段作用域
  if (cmd === 'cd') { trackCwd(words, idx + 1, ctx); return }
  if (cmd === 'pushd' || cmd === 'popd') { ctx.cwd = null; return }

  // $IFS 拼接使词法结构不可信：命中危险命令形态且存在拼接证据时要求确认
  if (/\b(rm|git|sh|bash|python|node|powershell|cmd)\b/.test(words[idx].value)
    && words.slice(idx).some((w) => IFS_RE.test(w.value) && (w.value.includes('-') || w.value.startsWith('rm') || w.value.startsWith('git')))) {
    addMatch(matches, mkMatch(findRule('shell/ifs-obfuscation'), '命令含 $IFS 拼接，词法结构不可信'))
    return
  }

  // alias 定义：提取 name='payload' 并分析负载（静态可见）
  if (cmd === 'alias') {
    const def = words[idx + 1]?.value
    if (def) {
      const eq = def.indexOf('=')
      if (eq !== -1 && eq < def.length - 1) {
        recurseCommand(def.slice(eq + 1), ctx, matches, '（位于 alias 定义内）')
      }
    }
    return
  }

  // 复合命令关键字：跳过关键字后按普通命令分析
  if (COMPOUND_KEYWORDS.has(cmd)) {
    dispatchCommand(words.slice(idx + 1), assignments, ctx, depth, matches, seg.heredocs)
    return
  }
  // ! 取反前缀：真实命令在 ! 之后（支持 ! { ... } 复合形式）
  if (cmd === '!') {
    if (words[idx + 1]?.value === '{') {
      analyzeSegment(segWithWords(seg, words.slice(idx + 1)), ctx, depth + 1, matches)
    } else {
      dispatchCommand(words.slice(idx + 1), assignments, ctx, depth, matches, seg.heredocs)
    }
    return
  }
  // function 关键字形式：function name() { ... } / function name { ... }
  if (cmd === 'function' && words[idx + 1] && words[idx + 2]?.value === '{') {
    analyzeSegment(segWithWords(seg, words.slice(idx + 2)), ctx, depth + 1, matches)
    return
  }

  // 函数定义：分析函数体（正文按普通命令分析）；支持 f(){ ... } 粘连形式
  if (FUNC_DEF_RE.test(cmd)) {
    const rest = words.slice(idx + 1)
    let body = []
    if (cmd.endsWith('{')) {
      for (const w of rest) {
        if (w.value === '}') break
        body.push(w.value)
      }
    } else {
      const open = rest.findIndex((w) => w.value === '{')
      if (open !== -1) {
        let depth2 = 0
        for (const w of rest.slice(open + 1)) {
          if (w.value === '{') depth2++
          else if (w.value === '}') {
            if (depth2 === 0) break
            depth2--
          }
          body.push(w.value)
        }
      }
    }
    if (body.length > 0) {
      recurseCommand(body.join(' '), ctx, matches, '（位于函数体内）')
    }
    return
  }

  // 大括号组：重新组词后递归分析
  if (cmd === '{') {
    let rest = words.slice(idx + 1)
    if (rest.length > 0 && rest[rest.length - 1].value === '}') rest = rest.slice(0, -1)
    analyzeSegment(segWithWords(seg, rest), ctx, depth + 1, matches)
    return
  }

  // eval：字面负载递归分析，动态负载 vigilant 才拦
  if (cmd === 'eval') {
    const payloadText = words.slice(idx + 1).map((w) => w.value).join(' ')
    if (payloadText) {
      if (/[\$`]/.test(payloadText)) {
        if (LEVEL_ORDER[ctx.policy.level] >= LEVEL_ORDER.vigilant) {
          addMatch(matches, mkMatch(findRule('shell/eval-dynamic'), `eval 参数含变量/替换: ${payloadText}`))
        }
      } else {
        recurseCommand(payloadText, ctx, matches)
      }
    }
    return
  }

  // source / .：记住的 heredoc 内容回放，否则 vigilant 才拦
  if (cmd === 'source' || cmd === '.') {
    const target = words[idx + 1]?.value
    if (target && ctx.heredocs.has(target)) {
      recurseCommand(ctx.heredocs.get(target), ctx, matches)
    } else if (LEVEL_ORDER[ctx.policy.level] >= LEVEL_ORDER.vigilant) {
      addMatch(matches, mkMatch(findRule('shell/source-unknown'), `source 目标 ${target ?? '(空)'} 内容未知`))
    }
    return
  }

  // PowerShell / cmd：载荷模式扫描
  if (POWER_CMDS.has(cmd)) {
    psAnalysis(words, idx + 1, matches)
    return
  }

  // 解释器直接吃 heredoc（python3 <<EOF ... EOF）：扫描正文中的删除类调用
  if (INTERP_CMDS.has(cmd) && seg.heredocs.length > 0) {
    for (const h of seg.heredocs) {
      if (DANGEROUS_CODE_RE.test(h.value)) {
        addMatch(matches, mkMatch(findRule('interp/embedded'), 'heredoc 脚本内含删除类系统调用'))
        break
      }
    }
  }

  // 统一分发（内含包装命令/shell/su 的迭代展开）
  dispatchCommand(words.slice(idx), assignments, ctx, depth, matches, seg.heredocs)
}

/** 用词列表重建命令段（保留原段的重定向与 heredoc 记录） */
function segWithWords(seg, wordTokens) {
  return { ...seg, words: wordTokens.map((w) => ({ type: 'word', value: w.value })) }
}

/** 命令分发：迭代展开包装命令/shell/su，最终落到具体命令分析器 */
function dispatchCommand(words, assignments, ctx, depth, matches, heredocs = []) {
  let w = words
  let envFromWrappers = {}
  let guard = 0
  while (w.length > 0 && guard < 8) {
    // fd 前缀数字与 ! 跳过（包装展开后可能再次出现，如 timeout 10 rm）
    while (w.length > 0 && (/^\d+$/.test(w[0].value) || w[0].value === '!')) w = w.slice(1)
    const cmd = w[0]?.value
    if (!cmd) return
    guard++
    if (WRAPPERS[cmd]) {
      const r = unwrapGeneric(w, 0, cmd)
      if (r.env) envFromWrappers = { ...envFromWrappers, ...r.env }
      if (r.kind === 'payload') {
        recurseCommand(r.text, ctx, matches)
        return
      }
      if (r.words.length === 0) return // 如 sudo -i 交互式登录
      w = r.words
      continue
    }
    if (SHELLS.has(cmd)) {
      shellScript(w, 1, ctx, depth, matches, heredocs)
      return
    }
    if (cmd === 'su') {
      suAnalysis(w, 1, ctx, depth, matches)
      return
    }
    switch (cmd) {
      case 'git':
        analyzeGit(w.slice(1), { ...envFromWrappers, ...assignments }, ctx, matches)
        return
      case 'rm':
        analyzeRm(w.slice(1), ctx, matches, { dynamicTarget: false })
        return
      case 'mv':
        analyzeMv(w.slice(1), ctx, matches)
        return
      case 'find':
        analyzeFind(w.slice(1), ctx, matches)
        return
      case 'xargs':
      case 'parallel':
        analyzeXargs(w.slice(1), ctx, matches)
        return
      case 'dd':
        analyzeDd(w.slice(1), matches)
        return
      case 'shred':
        addMatch(matches, mkMatch(findRule('fs/shred'), 'shred 将不可恢复地擦除文件'))
        return
      case 'chmod':
        analyzeModeChange(w.slice(1), ctx, matches, 'fs/chmod-recursive')
        return
      case 'chown':
        analyzeModeChange(w.slice(1), ctx, matches, 'fs/chown-recursive')
        return
      case 'reboot':
        addMatch(matches, mkMatch(findRule('sys/reboot'), '将重启系统'))
        return
      case 'Remove-Item':
      case 'rmdir':
      case 'rd':
      case 'del':
        windowsNative(w, matches)
        return
      default:
        break
    }
    if (SHUTDOWN_CMDS.has(cmd)) {
      addMatch(matches, mkMatch(findRule('sys/shutdown'), '将关闭或切断系统电源'))
      return
    }
    if (cmd.startsWith('mkfs') || cmd.startsWith('mkswap')) {
      analyzeMkfs(w.slice(1), matches)
      return
    }
    if (INTERP_CMDS.has(cmd)) {
      analyzeInterp(w.slice(1), matches)
      return
    }
    customRulesCheck(cmd, w, ctx, matches)
    return
  }
  // 包装链超过上限且仍有命令未分析：失败安全为需确认
  if (w.length > 0) {
    addMatch(matches, mkMatch(findRule('shell/depth-limit'), `包装嵌套超过 ${guard} 层，停止深入分析`))
  }
}

/** 通用包装命令展开：返回 {kind:'command', words, env} 或 {kind:'payload', text, env} */
function unwrapGeneric(words, idx, wrapper) {
  const spec = WRAPPERS[wrapper]
  const env = {}
  let i = idx + 1
  while (i < words.length) {
    const v = words[i].value
    if (v === '--') { i++; break }
    if (ASSIGN_RE.test(v)) {
      // env X=1 cmd 形式的环境赋值：收集起来供 git 等分析使用
      const eq = v.indexOf('=')
      env[v.slice(0, eq)] = v.slice(eq + 1)
      i++
      continue
    }
    // 位置参数（timeout 时长、chrt/taskset 优先级）可出现在选项之间
    if (spec.posValue && /^(\d+(\.\d+)?[smhd]?|0x[0-9a-fA-F]+)$/.test(v)) { i++; continue }
    if (spec.payloadFlag) {
      const longForm = spec.payloadLong ? v.startsWith(spec.payloadLong + '=') : false
      const shortForm = v === spec.payloadFlag || v.startsWith(spec.payloadFlag + '=')
      if (shortForm || longForm) {
        const prefix = longForm ? spec.payloadLong : spec.payloadFlag
        const payload = v.startsWith(prefix + '=') ? v.slice(prefix.length + 1) : words[i + 1]?.value
        return payload ? { kind: 'payload', text: payload, env } : { kind: 'command', words: [], env }
      }
    }
    if (!v.startsWith('-') || v === '-') break
    if (spec.values.includes(v)) { i += 2; continue }
    i++
  }
  return { kind: 'command', words: words.slice(i), env }
}

/** 递归分析一段子命令文本（预算减一，超限时由 depth-limit 兜底） */
function recurseCommand(text, ctx, matches, note) {
  const sub = analyzeCommand(text, { policy: ctx.policy, cwd: ctx.cwd, home: ctx.home, env: ctx.env, maxDepth: ctx.maxDepth - 1 })
  for (const m of sub.matches) addMatch(matches, note ? { ...m, message: m.message + note } : m)
}

/** shell 包装：-c 负载或脚本路径；heredoc 直喂 shell 时分析正文 */
function shellScript(words, start, ctx, depth, matches, heredocs = []) {
  // bash <<EOF ... EOF：正文直接作为脚本执行
  for (const h of heredocs) {
    recurseCommand(h.value, ctx, matches, '（heredoc 脚本内容）')
  }
  for (let i = start; i < words.length; i++) {
    const v = words[i].value
    if (v === '--') { i++; continue }
    if (v.startsWith('-') && v.length > 1) {
      if (v.startsWith('--')) continue
      if (v.includes('c')) {
        const payload = words[i + 1]?.value
        if (payload) recurseCommand(payload, ctx, matches)
        return
      }
      continue
    }
    // 脚本路径
    if (ctx.heredocs.has(v)) {
      recurseCommand(ctx.heredocs.get(v), ctx, matches)
    } else if (v === '-') {
      ctx.warnings.push(`脚本从标准输入读取，内容未审查: -`)
    } else {
      ctx.warnings.push(`脚本内容未知，未审查: ${v}`)
    }
    return
  }
}

/** su：-c 负载递归 */
function suAnalysis(words, start, ctx, depth, matches) {
  for (let i = start; i < words.length; i++) {
    const v = words[i].value
    if (v === '-c' || v === '--command' || v.startsWith('--command=')) {
      const payload = v.startsWith('--command=') ? v.slice('--command='.length) : words[i + 1]?.value
      if (payload) recurseCommand(payload, ctx, matches)
      return
    }
    if (v.startsWith('-')) continue
    // 用户参数
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return
  }
}

/** cd 跟踪 */
function trackCwd(words, start, ctx) {
  const args = words.slice(start)
  if (args.length === 0) { ctx.cwd = ctx.home; return }
  if (args.length !== 1) { ctx.cwd = null; return }
  let p = args[0].value
  if (p === '-' || /[\$`]/.test(p)) { ctx.cwd = null; return }
  if (p.startsWith('~')) p = path.join(ctx.home, p.slice(1))
  ctx.cwd = path.resolve(ctx.cwd ?? '/', p)
}

/** rm 分析 */
function analyzeRm(words, ctx, matches, { dynamicTarget }) {
  let recursive = false
  const targets = []
  for (const t of words) {
    const v = t.value
    if (v === '--') continue
    if (v === '--recursive') { recursive = true; continue }
    if (v === '--force') continue // 强制与否不影响分类
    if (v.startsWith('-') && v.length > 1) {
      for (const f of unbundleShort(v)) {
        if (f === '-r' || f === '-R') recursive = true
      }
      continue
    }
    targets.push(v)
  }
  // .git 元数据保护（无论是否递归）
  for (const t of targets) {
    if (containsGitMeta(t)) {
      addMatch(matches, mkMatch(findRule('fs/rm-git'), `目标 ${t} 位于 .git 内部`))
      return
    }
  }
  if (!recursive) return
  if (targets.length === 0) {
    if (dynamicTarget) addMatch(matches, mkMatch(findRule('fs/rm-dynamic'), '删除目标由上游动态提供'))
    return
  }
  for (const t of targets) {
    const m = classifyRmTarget(t, ctx)
    if (m) addMatch(matches, m)
  }
}

/** mv 分析：仅 .git 元数据保护 */
function analyzeMv(words, ctx, matches) {
  for (const t of words) {
    if (t.value.startsWith('-')) continue
    if (containsGitMeta(t.value)) {
      addMatch(matches, mkMatch(findRule('fs/rm-git'), `移动目标 ${t.value} 位于 .git 内部`))
      return
    }
  }
}

/** rm 目标分类 */
function classifyRmTarget(rawTarget, ctx) {
  let target = rawTarget
  if (target.includes('{}')) {
    return mkMatch(findRule('fs/rm-dynamic'), `目标 ${rawTarget} 含 xargs 替换占位符，按动态目标处理`)
  }
  if (target.includes('$') || target.includes('`')) {
    let expanded = false
    target = target.replace(/\$\{?HOME\}?/, (m) => { expanded = true; return ctx.home })
    target = target.replace(/\$\{?PWD\}?/, (m) => { expanded = true; return ctx.cwd ?? '' })
    if (!expanded) {
      return mkMatch(findRule('fs/rm-dynamic'), `目标 ${rawTarget} 含变量或命令替换，无法静态确认`)
    }
  }
  if (target.startsWith('~')) target = path.join(ctx.home, target.slice(1))
  if (WINDOWS_PATH_RE.test(target)) {
    return mkMatch(findRule('fs/rm-outside'), `目标 ${rawTarget} 为 Windows 绝对路径，按工作区外处理`)
  }
  // .git 判定先于通配截断（rm -rf .git* 同样致命）
  if (containsGitMeta(target)) return mkMatch(findRule('fs/rm-git'), `目标 ${rawTarget} 位于 .git 内部`)
  if (GLOB_CHARS_RE.test(target)) target = globPrefix(target)
  if (!ctx.cwd && !path.isAbsolute(target)) {
    return mkMatch(findRule('fs/rm-dynamic'), '当前工作目录未知，无法判定删除范围')
  }
  const resolved = path.resolve(ctx.cwd ?? '/', target)
  if (resolved === '/') return mkMatch(findRule('fs/rm-root'), `目标为根目录: ${rawTarget}`)
  if (resolved === ctx.home) return mkMatch(findRule('fs/rm-home'), `目标为用户主目录: ${rawTarget}`)
  if (containsGitMeta(resolved)) return mkMatch(findRule('fs/rm-git'), `目标 ${rawTarget} 位于 .git 内部`)
  if (ctx.cwd && isInside(resolved, ctx.workspace)) {
    return mkMatch(findRule('fs/rm-workspace'), `目标 ${rawTarget} 位于工作区内`)
  }
  if (resolved.startsWith(ctx.home + '/')) {
    return mkMatch(findRule('fs/rm-outside'), `目标 ${rawTarget} 位于主目录下`)
  }
  if (isTempPath(resolved, ctx.env)) return null
  if (!ctx.cwd) return mkMatch(findRule('fs/rm-dynamic'), '当前工作目录未知，无法判定删除范围')
  return mkMatch(findRule('fs/rm-outside'), `目标 ${rawTarget} 位于工作区外`)
}

/** 通配目标：取第一个含通配符段之前的最长前缀 */
function globPrefix(target) {
  const parts = target.split('/')
  const out = []
  for (const p of parts) {
    if (GLOB_CHARS_RE.test(p)) break
    out.push(p)
  }
  if (out.length === 0) return '.'
  return out.join('/') || '.'
}

function isTempPath(p, env) {
  for (const t of TEMP_PATHS) {
    if (p === t || p.startsWith(t + '/')) return true
  }
  if (env.TMPDIR && (p === env.TMPDIR || p.startsWith(env.TMPDIR + '/'))) return true
  return false
}

function isInside(target, cwd) {
  if (target === cwd) return true
  const rel = path.relative(cwd, target)
  return rel !== '..' && !rel.startsWith('../') && !path.isAbsolute(rel)
}

/** 判断路径是否包含 .git 目录段（按 / 与 \ 分隔；.git* 通配段同样命中） */
export function containsGitMeta(p) {
  return String(p).split(/[\\/]/).some((s) => s === '.git' || (s.startsWith('.git') && GLOB_CHARS_RE.test(s)))
}

/** git 分析 */
function analyzeGit(words, assignments, ctx, matches) {
  const envs = { ...ctx.exportedEnv, ...assignments } // 段内赋值优先，export 跨段可见
  let idx = 0
  while (idx < words.length) {
    const v = words[idx].value
    if (v === '-C' || v === '-c') { idx += 2; continue }
    if (v === '--') { idx++; continue } // 子命令前的选项终止符
    if (v.startsWith('--git-dir=') || v.startsWith('--work-tree=') || v.startsWith('--git-common-dir=') || v.startsWith('--namespace=')) { idx++; continue }
    if (v.startsWith('-') && v !== '--') { idx++; continue }
    break
  }
  const sub = words[idx]?.value
  if (!sub || sub.startsWith('-')) return
  idx++
  const spec = GIT_SUBS[sub]
  if (!spec) {
    // 未知子命令也可能有网络操作（GIT_SSH 保护兜底）
    if (NETWORK_SUBS.has(sub) && SSH_ENV_KEYS.some((k) => envs[k])) {
      addMatch(matches, mkMatch(findRule('git/ssh-env'), `网络子命令 ${sub} 携带 GIT_SSH* 环境覆盖`))
    }
    return
  }
  if (NETWORK_SUBS.has(sub) && SSH_ENV_KEYS.some((k) => envs[k])) {
    addMatch(matches, mkMatch(findRule('git/ssh-env'), `网络子命令 ${sub} 携带 GIT_SSH* 环境覆盖`))
  }

  const flags = []
  for (; idx < words.length; idx++) {
    const v = words[idx].value
    if (v === '--') { flags.push('--'); break }
    if (v.startsWith('--')) flags.push(v.split('=')[0])
    else if (v.startsWith('-') && v.length > 1) flags.push(...unbundleShort(v))
    else flags.push(v)
  }

  // 干跑检查（先于一切危险判定，--dry-run/-n 永不执行）
  if (spec.dryShorts?.some((f) => flags.includes('-' + f)) || spec.dryLongs?.some((f) => flags.includes(f))) return

  // push 空源 refspec（git push origin :branch）等价删除远端分支；+ 前缀为强制更新
  if (sub === 'push') {
    if (flags.some((f) => /^:[^:]+$/.test(f))) {
      addMatch(matches, mkMatch(findRule('git/push-delete'), '空源 refspec 将删除远端分支'))
      return
    }
    if (flags.some((f) => /^\+[^:]/.test(f))) {
      addMatch(matches, mkMatch(findRule('git/push-force'), '+ 前缀 refspec 强制更新远端分支'))
      return
    }
  }

  // stash: 第二个位置参数判定
  if (sub === 'stash') {
    const sub2 = flags[0]
    if (sub2 === 'drop') { addMatch(matches, mkMatch(findRule('git/stash-drop'), '丢弃 stash')); return }
    if (sub2 === 'clear') { addMatch(matches, mkMatch(findRule('git/stash-clear'), '清空全部 stash')); return }
    return
  }

  // checkout -- 丢弃工作区
  if (sub === 'checkout' && flags.includes('--')) {
    addMatch(matches, mkMatch(findRule('git/checkout-discard'), 'git checkout -- 将工作区重置为暂存区内容'))
    return
  }

  // restore: --staged 且无 --worktree 时放行
  if (sub === 'restore') {
    const staged = flags.includes('--staged')
    const worktree = flags.includes('--worktree')
    if (!staged || worktree) addMatch(matches, mkMatch(findRule('git/restore-worktree'), '将工作区文件还原为索引或提交内容'))
    return
  }

  // branch: -D / (--delete 且 --force/-f) 为删除；-f/--force 单独出现为强制移动
  if (sub === 'branch') {
    const force = flags.includes('-f') || flags.includes('--force')
    if (flags.includes('-D') || (flags.includes('--delete') && force)) {
      addMatch(matches, mkMatch(findRule('git/branch-delete-force'), '强制删除分支'))
      return
    }
    if (force) {
      addMatch(matches, mkMatch(findRule('git/branch-force-move'), '强制移动分支'))
      return
    }
  }

  // 短旗标
  if (spec.shorts) {
    for (const [f, ruleId] of Object.entries(spec.shorts)) {
      if (flags.includes('-' + f)) { addMatch(matches, mkMatch(findRule(ruleId), ruleText(ruleId))); return }
    }
  }
  // 长旗标（支持唯一前缀）
  if (spec.longs) {
    const hit = matchLongFlag(flags, spec.longs)
    if (hit) { addMatch(matches, mkMatch(findRule(hit), ruleText(hit))) }
  }
  // 组合条件（pair）
  if (spec.pair && spec.pair.length > 0 && spec.pair.every((f) => flags.includes(f))) {
    const ruleId = spec.longs[spec.pair[1]] ?? 'git/branch-delete-force'
    addMatch(matches, mkMatch(findRule(ruleId), ruleText(ruleId)))
  }
}

function ruleText(ruleId) {
  return findRule(ruleId)?.reason ?? ruleId
}

/** 长旗标匹配：精确优先，其次唯一前缀；前缀命中多个不同规则时视为不匹配 */
function matchLongFlag(flags, longs) {
  for (const f of flags) {
    if (!f.startsWith('--') || f === '--') continue
    if (longs[f]) return longs[f]
    const hits = new Set()
    for (const [k, ruleId] of Object.entries(longs)) {
      if (k.startsWith(f)) hits.add(ruleId)
    }
    if (hits.size === 1) return [...hits][0]
  }
  return null
}

/** 短旗标解绑：-fD → [-f, -D] */
export function unbundleShort(v) {
  if (v.startsWith('--')) return [v]
  if (v.length <= 2) return [v]
  return [...v.slice(1)].map((c) => '-' + c)
}

/** find 分析：-delete 与 -exec rm（负载先剥离包装命令） */
function analyzeFind(words, ctx, matches) {
  let del = false
  let findPath = null
  let execPayload = null
  for (let i = 0; i < words.length; i++) {
    const v = words[i].value
    if (v.startsWith('-') && v.length > 1) {
      if (v === '-delete') del = true
      if (v === '-exec' || v === '-execdir') {
        const payload = []
        let j = i + 1
        while (j < words.length && words[j].value !== ';' && words[j].value !== '+') {
          payload.push({ type: 'word', value: words[j].value })
          j++
        }
        execPayload = payload
        i = j
      }
      continue
    }
    if (!findPath) findPath = v
  }
  if (del) addMatch(matches, mkMatch(findRule('fs/find-delete'), 'find -delete 按条件批量删除文件'))
  if (execPayload && execPayload.length > 0) {
    const stripped = stripWrappers(execPayload)
    if (stripped[0]?.value === 'rm') {
      const target = findPath ?? '.'
      const m = classifyRmTarget(target, ctx)
      if (m) addMatch(matches, m)
    } else if (stripped[0] && SHELLS.has(stripped[0].value)) {
      const cIdx = stripped.findIndex((p) => p.value.startsWith('-') && p.value.includes('c'))
      if (cIdx !== -1 && stripped[cIdx + 1]) {
        recurseCommand(stripped[cIdx + 1].value, ctx, matches)
      }
    }
  }
}

/** xargs/parallel：负载命令按动态目标分析（先剥离包装命令） */
function analyzeXargs(words, ctx, matches) {
  let i = 0
  while (i < words.length) {
    const v = words[i].value
    if (v.startsWith('-') && v.length > 1) {
      if (['-I', '-d', '-n', '-L', '-P', '-E', '-a', '--max-args', '--max-lines'].includes(v)) i += 2
      else i++
      continue
    }
    break
  }
  const payload = stripWrappers(words.slice(i))
  if (payload[0]?.value === 'rm') {
    analyzeRm(payload.slice(1), ctx, matches, { dynamicTarget: true })
  } else if (payload[0] && SHELLS.has(payload[0].value)) {
    const cIdx = payload.findIndex((p) => p.value.startsWith('-') && p.value.includes('c'))
    if (cIdx !== -1 && payload[cIdx + 1]) {
      recurseCommand(payload[cIdx + 1].value, ctx, matches)
    }
  }
}

/** dd 分析：以最后一个 of= 为准（真实 dd 语义） */
function analyzeDd(words, matches) {
  let lastOf = null
  for (const w of words) {
    if (w.value.startsWith('of=')) lastOf = w.value.slice(3)
  }
  if (lastOf === null) return
  if (!lastOf.startsWith('/dev/')) return
  const dev = lastOf.slice('/dev/'.length)
  if (SAFE_DEV_TARGETS.has(dev)) return
  const severity = BLOCK_DEV_RE.test(lastOf) ? 'critical' : 'high'
  addMatch(matches, mkMatch(findRule('fs/dd-device'), `dd 将向设备 ${lastOf} 写入`, severity))
}

/** mkfs 分析 */
function analyzeMkfs(words, matches) {
  for (const w of words) {
    const v = w.value
    if (v.startsWith('-')) continue
    if (v.startsWith('/dev/')) {
      addMatch(matches, mkMatch(findRule('fs/mkfs-device'), `将格式化设备 ${v}`))
      return
    }
    if (v.startsWith('/') || v.startsWith('.') || v.startsWith('~')) {
      addMatch(matches, mkMatch(findRule('fs/mkfs-image'), `将格式化目标 ${v}`))
      return
    }
  }
}

/** chmod/chown 递归权限操作 */
export function analyzeModeChange(words, ctx, matches, ruleId) {
  let recursive = false
  let target = null
  for (const w of words) {
    const v = w.value
    if (v === '--recursive' || v === '-R') { recursive = true; continue }
    if (v.startsWith('-') && v.length > 1) { if (unbundleShort(v).includes('-R')) recursive = true; continue }
    if (v === '--') continue
    // 跳过模式/属主参数（chmod: 777/a+x; chown: user:group）
    if (ruleId === 'fs/chmod-recursive' && (/^[0-7]+$/.test(v) || /^[ugoa]*[+=-][rwxXstugo]*$/.test(v))) continue
    if (ruleId === 'fs/chown-recursive' && v.includes(':') && !target) continue
    target = v
  }
  if (!recursive || !target) return
  let t = target
  if (t.startsWith('~')) t = path.join(ctx.home, t.slice(1))
  if (GLOB_CHARS_RE.test(t)) t = globPrefix(t)
  const resolved = path.resolve(ctx.cwd ?? '/', t)
  let severity = 'medium'
  if (resolved === '/') severity = 'critical'
  else if (resolved === ctx.home || resolved.startsWith(ctx.home + '/')) severity = 'high'
  addMatch(matches, mkMatch(findRule(ruleId), `递归修改目标 ${target} 的${ruleId === 'fs/chmod-recursive' ? '权限' : '属主'}`, severity))
}

/** 解释器 -c/-e 单行内嵌代码扫描 */
function analyzeInterp(words, matches) {
  const codeFlags = new Set(['-c', '-e', '-r'])
  for (let i = 0; i < words.length; i++) {
    const v = words[i].value
    if (v === '-m' || v === '--module' || v === '-p' || v === '--profile') { i++; continue }
    if (codeFlags.has(v)) {
      const code = words[i + 1]?.value
      if (code && DANGEROUS_CODE_RE.test(code)) {
        addMatch(matches, mkMatch(findRule('interp/embedded'), '单行脚本内包含删除类系统调用'))
      }
      return
    }
    if (v.startsWith('-')) continue
  }
}

/** PowerShell / cmd 载荷扫描 */
function psAnalysis(words, start, matches) {
  const payload = words.slice(start).map((w) => w.value).join(' ')
  if (payload.includes('-EncodedCommand')) {
    addMatch(matches, mkMatch(findRule('sys/powershell-opaque'), '编码命令内容无法静态审查'))
    return
  }
  // 拆分为两个线性测试，避免 [\s\S]* 的二次方回溯
  const hasRm = /(?:Remove-Item|rm)\b/i.test(payload)
  if (hasRm && /-(?:Recurse|Force)\b|-r\b|-f\b/i.test(payload)) {
    addMatch(matches, mkMatch(findRule('sys/powershell-remove'), '强制递归删除'))
    return
  }
  if (/(?:rmdir|rd|del)\b[\s\S]{0,512}\/(?:s|q)/i.test(payload)) {
    addMatch(matches, mkMatch(findRule('sys/cmd-del'), 'cmd 递归静默删除'))
  }
}

/** Windows 原生命令的独立形态（不经 powershell/cmd 前缀） */
function windowsNative(words, matches) {
  const text = words.map((w) => w.value).join(' ')
  const cmd = words[0].value
  if (cmd === 'Remove-Item' && /-(?:Recurse|R)\b/i.test(text) && /-(?:Force|F)\b/i.test(text)) {
    addMatch(matches, mkMatch(findRule('sys/powershell-remove'), 'Remove-Item 强制递归删除'))
    return
  }
  if ((cmd === 'rmdir' || cmd === 'rd') && /\/s\b/i.test(text)) {
    addMatch(matches, mkMatch(findRule('sys/cmd-del'), 'rmdir /s 递归删除目录'))
    return
  }
  if (cmd === 'del' && /\/s\b/i.test(text) && /\/q\b/i.test(text)) {
    addMatch(matches, mkMatch(findRule('sys/cmd-del'), 'del /s /q 批量静默删除'))
  }
}

/** 自定义规则（策略 rules 字段） */
function customRulesCheck(cmd, words, ctx, matches) {
  for (const rule of ctx.policy.customRules) {
    if (rule.command !== cmd) continue
    if (rule.subcommand && words[1]?.value !== rule.subcommand) continue
    const argValues = words.slice(1).map((t) => t.value)
    let hit = false
    for (const a of rule.args) {
      if (argValues.includes(a)) { hit = true; break }
      for (const v of argValues) {
        if (v.startsWith('-') && v.length > 2 && unbundleShort(v).includes(a)) { hit = true; break }
      }
      if (hit) break
    }
    if (hit) addMatch(matches, mkMatch(rule, rule.reason))
  }
}

/** 粗粒度扫描（分词失败或输入超长时的兜底） */
function rawScan(text, ctx) {
  const matches = []
  const warnings = []
  const head = text.trimStart()
  const m = /^(\S+)(?:\s+(\S+))?/.exec(head)
  const first = m?.[1] ?? ''
  const second = m?.[2] ?? ''
  // 展示类命令豁免仅在无命令分隔符（单条命令）时成立；
  // echo a; rm -rf / 这类链式命令仍须扫描后续段
  const exempt = !RAW_BOUNDARY_RE.test(text)
    && (RAW_EXEMPT_FIRST.has(first) || RAW_EXEMPT_PAIR.has(`${first} ${second}`))
  if (exempt) {
    warnings.push(`命令以展示类命令 ${first} 开头，跳过粗粒度扫描`)
    return { matches, warnings }
  }
  for (const p of RAW_PATTERNS) {
    if (p.re.test(text)) {
      addMatch(matches, mkMatch(findRule(p.rule), `粗粒度扫描命中: ${p.rule}`))
    }
  }
  return { matches, warnings }
}

/** 按 ruleId 去重合并命中，保留最严重的一条 */
export function addMatch(matches, m) {
  const i = matches.findIndex((x) => x.ruleId === m.ruleId)
  if (i === -1) { matches.push(m); return }
  const rank = (s) => (s === 'critical' ? 3 : s === 'high' ? 2 : 1)
  if (rank(m.severity) > rank(matches[i].severity)) matches[i] = m
}
