#!/usr/bin/env node
// Barricade CLI：分析/检查/hook/门卫/策略/规则/审计
import fs from 'node:fs'
import os from 'node:os'
import { analyzeCommand } from '../src/analyzer.js'
import { Policy } from '../src/policy.js'
import { confirmEntry } from '../src/prompt.js'
import { Auditor } from '../src/audit.js'
import { runThroughShell, waitExit } from '../src/executor.js'
import { BUILTIN_RULES, LEVELS } from '../src/rules.js'

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const VERSION = pkg.version

const USAGE = `barricade ${VERSION} — 编码 agent 的破坏性命令拦截闸门

usage: barricade <子命令> [选项]

子命令:
  analyze [--json] <命令>       分析一条命令并输出判定（不执行）
  check   [--json] [--quiet] <命令>   判定命令; 放行退出 0, 拦截退出 1
  gate -- <命令>                分析 + 交互确认 + 执行（终端包装模式）
  hook                          harness hook: stdin 读入命令/JSON, stdout 输出判定 JSON
  policy  --show [--json]       显示合并后的策略
  policy  --validate [--policy F]  校验策略文件, 打印警告与 OK
  rules   [--json]              列出内置规则
  audit   [--tail N]            查看最近审计记录

选项:
  -c, --command <命令>          直接提供命令文本
  --stdin                       从标准输入读取命令
  --level <relaxed|balanced|vigilant>  临时等级（显式覆盖策略文件）
  --policy <文件>               指定用户策略文件
  --json                        输出 JSON
  --quiet                       静默（仅退出码）
  --exit-on-block               hook 拦截时退出码为 1
  --tail <N>                    审计条数（默认 20）
  -h, --help                    帮助
  -v, --version                 版本

示例:
  barricade check -c "rm -rf /"            # 退出 1
  barricade analyze --json -c "git push --force x"
  echo '{"command":"rm -rf /"}' | barricade hook
  barricade gate -- "npm run build"        # 交互确认后执行`

function parseArgs(argv) {
  const opts = { command: null, flags: {}, positional: [], rest: [] }
  let i = 0
  const take = (name) => {
    const v = argv[i + 1]
    // 拒绝把下一个旗标当作值吞掉（-c --json 这类输入按用法错误处理）
    if (v === undefined || (v.startsWith('-') && v !== '-')) return undefined
    i += 2
    return v
  }
  while (i < argv.length) {
    const a = argv[i]
    if (a === '--') { opts.rest = argv.slice(i + 1); break }
    if (a === '-c' || a === '--command') { opts.flags.command = take(a); continue }
    if (a === '--level') { opts.flags.level = take(a); continue }
    if (a === '--policy') { opts.flags.policy = take(a); continue }
    if (a === '--tail') { opts.flags.tail = take(a); continue }
    if (a === '--stdin') { opts.flags.stdin = true; i++; continue }
    if (a === '--json') { opts.flags.json = true; i++; continue }
    if (a === '--quiet') { opts.flags.quiet = true; i++; continue }
    if (a === '--show') { opts.flags.show = true; i++; continue }
    if (a === '--validate') { opts.flags.validate = true; i++; continue }
    if (a === '--exit-on-block') { opts.flags.exitOnBlock = true; i++; continue }
    if (a === '-h' || a === '--help') { opts.flags.help = true; i++; continue }
    if (a === '-v' || a === '--version') { opts.flags.version = true; i++; continue }
    if (!opts.command) opts.command = a
    else opts.positional.push(a)
    i++
  }
  return opts
}

function getCommandText(opts) {
  if (opts.flags.command !== undefined) return opts.flags.command
  if (opts.rest.length > 0) return opts.rest.join(' ')
  if (opts.positional.length > 0) return opts.positional.join(' ')
  if (opts.flags.stdin) return fs.readFileSync(0, 'utf8')
  return null
}

function loadPolicy(flags) {
  const env = { ...process.env }
  if (flags.policy) env.BARRICADE_POLICY = flags.policy
  const { policy, warnings } = Policy.load({ env, cwd: process.cwd() })
  for (const w of warnings) process.stderr.write(`[barricade] 警告: ${w}\n`)
  if (flags.level) {
    if (!LEVELS.includes(flags.level)) {
      console.error(`未知等级 "${flags.level}"（可选: ${LEVELS.join('/')}）`)
      process.exit(2)
    }
    return policy.withLevel(flags.level)
  }
  return policy
}

function auditBlocked(verdict) {
  Auditor.fromEnv().append({
    action: verdict.action,
    severity: verdict.severity,
    ruleIds: verdict.matches.map((m) => m.ruleId),
    command: verdict.command,
    cwd: process.cwd(),
  })
}

function analyzeWithEnv(cmd, policy, extraCwd) {
  return analyzeCommand(cmd, { policy, cwd: extraCwd ?? process.cwd(), home: os.homedir(), env: process.env })
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))

  if (opts.flags.version) { console.log(`barricade ${VERSION}`); return }
  if (opts.flags.help) { console.log(USAGE); return }
  if (!opts.command) { console.log(USAGE); process.exit(2) }

  // 管道下游关闭（如 | head -1）时不崩溃
  process.stdout.on('error', () => process.exit(0))
  process.stderr.on('error', () => {})

  switch (opts.command) {
    case 'analyze': {
      const cmd = getCommandText(opts)
      if (cmd === null) { console.error('缺少命令输入（用 -c 或 -- 提供）'); process.exit(2) }
      const policy = loadPolicy(opts.flags)
      const verdict = analyzeWithEnv(cmd, policy)
      if (verdict.action !== 'allow') auditBlocked(verdict)
      if (opts.flags.json) console.log(JSON.stringify(verdict.toJSON(), null, 2))
      else console.log(verdict.action === 'allow' ? '放行' : verdict.format())
      // analyze 只输出判定，退出码恒 0（用法错误除外）；需要退出码语义时用 check
      break
    }
    case 'check': {
      const cmd = getCommandText(opts)
      if (cmd === null) { console.error('缺少命令输入（用 -c 或 -- 提供）'); process.exit(2) }
      const policy = loadPolicy(opts.flags)
      const verdict = analyzeWithEnv(cmd, policy)
      if (verdict.action !== 'allow') auditBlocked(verdict)
      if (opts.flags.json) console.log(JSON.stringify(verdict.toJSON(), null, 2))
      else if (!opts.flags.quiet) console.log(verdict.action === 'allow' ? '放行' : verdict.format())
      process.exit(verdict.action === 'allow' ? 0 : 1)
      break
    }
    case 'hook': {
      const raw = fs.readFileSync(0, 'utf8').trim()
      let command = raw
      let cwd = null
      try {
        const j = JSON.parse(raw)
        command = j.command ?? j.text ?? raw
        cwd = typeof j.cwd === 'string' ? j.cwd : null
      } catch { /* 视为纯命令文本 */ }
      if (typeof command !== 'string') {
        // 协议违约：命令字段类型异常 → 拒绝
        console.log(JSON.stringify({ command: '', action: 'deny', severity: 'high', reason: 'hook 输入的命令字段不是字符串，拒绝执行', matches: [], warnings: ['协议违约'] }))
        if (opts.flags.exitOnBlock) process.exit(1)
        break
      }
      const policy = loadPolicy(opts.flags)
      const verdict = analyzeWithEnv(command, policy, cwd)
      if (verdict.action !== 'allow') auditBlocked(verdict)
      console.log(JSON.stringify(verdict.toJSON()))
      if (opts.flags.exitOnBlock && verdict.action !== 'allow') process.exit(1)
      break
    }
    case 'gate': {
      const cmd = getCommandText(opts)
      if (cmd === null) { console.error('缺少命令输入（gate 需要 -- 后的命令）'); process.exit(2) }
      const policy = loadPolicy(opts.flags)
      const verdict = analyzeWithEnv(cmd, policy)
      if (verdict.action !== 'allow') auditBlocked(verdict)

      const tty = Boolean(process.stdin.isTTY && process.stdout.isTTY)
      let decision = 'allow'
      if (verdict.action !== 'allow') {
        const result = await confirmEntry(
          { command: cmd, severity: verdict.severity, matches: verdict.matches },
          { tty, input: process.stdin, output: process.stdout, policy, session: new Set(), timeoutMs: policy.confirmation.timeoutSeconds * 1000 },
        )
        decision = result.decision
      }
      if (decision === 'allow' || decision === 'session' || decision === 'always') {
        if (verdict.action !== 'allow') {
          Auditor.fromEnv().append({ action: 'allow', severity: verdict.severity, ruleIds: verdict.matches.map((m) => m.ruleId), command: cmd, cwd: process.cwd() })
        }
        const child = runThroughShell(cmd, process.env)
        const code = await waitExit(child)
        process.exit(code)
      }
      console.error('已取消执行')
      process.exit(1)
      break
    }
    case 'policy': {
      if (opts.flags.validate) {
        if (opts.flags.policy && !fs.existsSync(opts.flags.policy)) {
          console.error(`策略文件不存在: ${opts.flags.policy}`)
          process.exit(1)
        }
        const { policy, warnings } = Policy.load({
          env: { ...process.env, ...(opts.flags.policy ? { BARRICADE_POLICY: opts.flags.policy } : {}) },
          cwd: process.cwd(),
        })
        for (const w of warnings) console.log(`警告: ${w}`)
        console.log(`OK（level=${policy.level}, allowlist=${policy.allowlist.length}, rules=${policy.customRules.length}, 来源: ${policy.sources.join(', ') || '默认'}）`)
        process.exit(warnings.length > 0 ? 1 : 0)
      } else {
        const policy = loadPolicy(opts.flags)
        if (opts.flags.json) console.log(JSON.stringify(policy.toJSON(), null, 2))
        else {
          console.log(`等级: ${policy.level}`)
          console.log(`failClosed: ${policy.failClosed}`)
          console.log(`allowlist: ${policy.allowlist.join('; ') || '(空)'}`)
          console.log(`overrides: ${Object.entries(policy.overrides).map(([k, v]) => `${k}=${v}`).join('; ') || '(空)'}`)
          console.log(`自定义规则: ${policy.customRules.length} 条`)
        }
      }
      break
    }
    case 'rules': {
      if (opts.flags.json) {
        console.log(JSON.stringify(BUILTIN_RULES, null, 2))
      } else {
        for (const r of BUILTIN_RULES) {
          console.log(`${r.id.padEnd(24)} [${r.severity}] ${r.title}`)
        }
      }
      break
    }
    case 'audit': {
      const raw = Number(opts.flags.tail)
      const n = Number.isNaN(raw) || raw < 0 ? 20 : Math.floor(raw)
      const rows = Auditor.fromEnv().tail(n)
      for (const r of rows) console.log(JSON.stringify(r))
      break
    }
    default:
      console.error(`未知子命令: ${opts.command}`)
      console.log(USAGE)
      process.exit(2)
  }
}

main().catch((e) => {
  console.error(`[barricade] 内部错误: ${e.message}`)
  process.exit(2)
})
