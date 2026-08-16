import test from 'node:test'
import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { mkdtempSync } from 'node:fs'
import { confirmEntry } from '../src/prompt.js'
import { Policy } from '../src/policy.js'

function streams() {
  return { input: new PassThrough(), output: new PassThrough() }
}
function policyFile() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'barricade-prompt-'))
  const file = path.join(dir, 'p.json')
  fs.writeFileSync(file, JSON.stringify({ level: 'balanced' }))
  return { dir, file }
}
function entry() {
  return {
    command: 'rm -rf /',
    severity: 'critical',
    matches: [{ ruleId: 'fs/rm-root', severity: 'critical', message: '删除根目录' }],
  }
}

async function run(keys, opts = {}) {
  const { input, output } = streams()
  const done = confirmEntry(entry(), {
    tty: true,
    input,
    output,
    policy: opts.policy,
    session: opts.session ?? new Set(),
    timeoutMs: opts.timeoutMs ?? 0,
  })
  if (keys) input.write(keys)
  const result = await done
  return { result, output: output.read() ?? '' }
}

test('y → 放行', async () => {
  const { result } = await run('y\n')
  assert.equal(result.decision, 'allow')
})

test('n → 拒绝', async () => {
  const { result } = await run('n\n')
  assert.equal(result.decision, 'deny')
})

test('s → 会话放行并记录规则', async () => {
  const session = new Set()
  const { result } = await run('s\n', { session })
  assert.equal(result.decision, 'session')
  assert.ok(session.has('fs/rm-root'))
})

test('a → 永久放行写入策略文件', async () => {
  const pf = policyFile()
  const policy = Policy.load({ env: { ...process.env, BARRICADE_POLICY: pf.file }, cwd: pf.dir }).policy
  const { input, output } = streams()
  const done = confirmEntry(
    { command: 'git push --force x', severity: 'high', matches: [{ ruleId: 'git/push-force', severity: 'high', message: '强制推送覆盖远端历史' }] },
    { tty: true, input, output, policy, session: new Set(), timeoutMs: 0 },
  )
  input.write('a\n')
  const r = await done
  assert.equal(r.decision, 'always')
  const reloaded = Policy.load({ env: { ...process.env, BARRICADE_POLICY: pf.file }, cwd: pf.dir }).policy
  assert.equal(reloaded.overrides['git/push-force'], 'allow')
})

test('致命规则不可永久放行 → 重新询问', async () => {
  const pf = policyFile()
  const policy = Policy.load({ env: { ...process.env, BARRICADE_POLICY: pf.file }, cwd: pf.dir }).policy
  const { result } = await run('a\ny\n', { policy })
  assert.equal(result.decision, 'allow')
  const reloaded = Policy.load({ env: { ...process.env, BARRICADE_POLICY: pf.file }, cwd: pf.dir }).policy
  assert.equal(reloaded.overrides['fs/rm-root'], undefined)
})

test('无效输入后重新询问', async () => {
  const { result } = await run('x\nn\n')
  assert.equal(result.decision, 'deny')
})

test('q → 拒绝', async () => {
  const { result } = await run('q\n')
  assert.equal(result.decision, 'deny')
})

test('超时 → 拒绝', async () => {
  const { result } = await run(null, { timeoutMs: 100 })
  assert.equal(result.decision, 'deny')
})

test('非 TTY → 直接拒绝', async () => {
  const { input, output } = streams()
  const result = await confirmEntry(entry(), { tty: false, input, output, policy: Policy.fromObject({}), session: new Set(), timeoutMs: 0 })
  assert.equal(result.decision, 'deny')
})

test('输入流关闭（EOF）→ 拒绝而非挂起', async () => {
  const { input, output } = streams()
  const done = confirmEntry(entry(), { tty: true, input, output, policy: Policy.fromObject({}), session: new Set(), timeoutMs: 0 })
  input.end()
  const r = await done
  assert.equal(r.decision, 'deny')
})

test('输出包含命令与命中规则', async () => {
  const pf = policyFile()
  const policy = Policy.load({ env: { ...process.env, BARRICADE_POLICY: pf.file }, cwd: pf.dir }).policy
  const { output } = await run('n\n', { policy })
  assert.ok(output.includes('rm -rf /'))
  assert.ok(output.includes('fs/rm-root'))
})
