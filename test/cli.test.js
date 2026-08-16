import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'

const BIN = path.resolve('bin/barricade.js')

function run(args, opts = {}) {
  const env = {
    ...process.env,
    BARRICADE_HOME: opts.home ?? tempHome(),
    BARRICADE_POLICY: opts.policyFile ?? '',
    ...(opts.envExtra ?? {}),
  }
  return execFileSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    input: opts.input,
    env,
    windowsHide: true,
  })
}
function runStatus(args, opts = {}) {
  try {
    return { code: 0, stdout: run(args, opts) }
  } catch (e) {
    return { code: e.status, stdout: e.stdout ?? '' }
  }
}
function tempHome() {
  return mkdtempSync(path.join(os.tmpdir(), 'barricade-home-'))
}

test('check：安全命令退出码 0', () => {
  const r = runStatus(['check', '--command', 'echo hi'])
  assert.equal(r.code, 0)
})

test('check：危险命令退出码 1（非交互环境按拦截处理）', () => {
  const r = runStatus(['check', '--command', 'rm -rf /'])
  assert.equal(r.code, 1)
  assert.ok(r.stdout.includes('fs/rm-root'))
})

test('check --json：输出结构化判定', () => {
  const r = runStatus(['check', '--json', '--command', 'git push --force x'])
  assert.equal(r.code, 1)
  const j = JSON.parse(r.stdout)
  assert.equal(j.action, 'ask')
  assert.equal(j.matches[0].ruleId, 'git/push-force')
})

test('analyze --json：放行判定', () => {
  const j = JSON.parse(run(['analyze', '--json', '--command', 'ls -la']))
  assert.equal(j.action, 'allow')
})

test('analyze --json：致命判定', () => {
  const j = JSON.parse(run(['analyze', '--json', '--command', 'rm -rf /']))
  assert.equal(j.action, 'deny')
  assert.equal(j.severity, 'critical')
})

test('hook：stdin JSON 契约输出判定 JSON 且退出 0', () => {
  const out = run(['hook'], { input: JSON.stringify({ command: 'rm -rf /', cwd: '/work' }) })
  const j = JSON.parse(out)
  assert.equal(j.action, 'deny')
  const out2 = run(['hook'], { input: JSON.stringify({ command: 'git status' }) })
  assert.equal(JSON.parse(out2).action, 'allow')
})

test('hook：原始字符串 stdin 亦可', () => {
  const j = JSON.parse(run(['hook'], { input: 'git reset --hard' }))
  assert.equal(j.action, 'ask')
})

test('hook --exit-on-block：拦截时退出 1', () => {
  const r = runStatus(['hook', '--exit-on-block'], { input: JSON.stringify({ command: 'rm -rf /' }) })
  assert.equal(r.code, 1)
})

test('rules --json：列出内置规则', () => {
  const rules = JSON.parse(run(['rules', '--json']))
  assert.ok(Array.isArray(rules))
  assert.ok(rules.some((r) => r.id === 'git/reset-hard'))
})

test('policy --show：输出合并后的策略', () => {
  const j = JSON.parse(run(['policy', '--show', '--json']))
  assert.equal(j.level, 'balanced')
})

test('policy --validate：合法文件通过', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'barricade-val-'))
  const file = path.join(dir, 'p.json')
  fs.writeFileSync(file, JSON.stringify({ level: 'vigilant', allowlist: ['git status'] }))
  const out = run(['policy', '--validate', '--policy', file])
  assert.ok(out.includes('OK'))
})

test('gate：安全命令真实执行', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'barricade-gate-'))
  const marker = path.join(dir, 'marker.txt')
  const cmd = process.platform === 'win32' ? `echo ok > "%MARKER%"` : `echo ok > "$MARKER"`
  const r = runStatus(['gate', '--', cmd], { home: dir, envExtra: { MARKER: marker } })
  assert.equal(r.code, 0)
  assert.equal(fs.readFileSync(marker, 'utf8').trim(), 'ok')
  // 不应在仓库根目录留下字面 %MARKER% 文件（POSIX 下未经展开的兜底检查）
  assert.equal(fs.existsSync(path.resolve('%MARKER%')), false)
})

test('gate：危险命令被拦截且不执行', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'barricade-gate-'))
  const victim = path.join(dir, 'victim')
  fs.mkdirSync(victim)
  const keep = path.join(victim, 'keep.txt')
  fs.writeFileSync(keep, 'data')
  const cmd = `rm -rf "${victim}"`
  const r = runStatus(['gate', '--', cmd], { home: dir })
  assert.equal(r.code, 1)
  assert.ok(fs.existsSync(keep), '危险命令不应被执行')
  assert.ok(r.stdout.includes('拦截'))
})

test('gate：致命命令同样被拦截', () => {
  const r = runStatus(['gate', '--', 'rm -rf /'], { home: tempHome() })
  assert.equal(r.code, 1)
})

test('缺少子命令 → 用法错误退出码 2', () => {
  const r = runStatus([])
  assert.equal(r.code, 2)
  assert.ok(r.stdout.includes('usage'))
})

test('--help 正常输出', () => {
  const out = run(['--help'])
  assert.ok(out.includes('barricade'))
})

test('--level 非法值 → 用法错误退出码 2', () => {
  const r = runStatus(['analyze', '--level', 'bogus', '--command', 'ls'])
  assert.equal(r.code, 2)
})

test('hook：命令字段非字符串 → 拒绝 JSON', () => {
  const out = run(['hook'], { input: JSON.stringify({ command: 42 }) })
  const j = JSON.parse(out)
  assert.equal(j.action, 'deny')
})
