import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { mkdtempSync } from 'node:fs'
import { Policy } from '../src/policy.js'

function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), 'barricade-policy-'))
}

test('默认策略', () => {
  const p = Policy.fromObject({})
  assert.equal(p.level, 'balanced')
  assert.equal(p.failClosed, false)
  assert.deepEqual(p.allowlist, [])
  assert.deepEqual(p.overrides, {})
  assert.deepEqual(p.customRules, [])
})

test('非法字段被挽救为默认值并给出警告', () => {
  const { policy, warnings } = Policy.parse({ level: 'nonsense', allowlist: 'not-array' })
  assert.equal(policy.level, 'balanced')
  assert.deepEqual(policy.allowlist, [])
  assert.ok(warnings.length >= 2)
})

test('非法自定义规则被丢弃并警告', () => {
  const { policy, warnings } = Policy.parse({
    rules: [
      { id: 'a', command: 'x', args: [], severity: 'high', reason: 'ok' },
      { id: '', command: 'y', args: [], severity: 'high', reason: '缺 id' },
      { id: 'b', command: 'z', args: [], severity: 'nope', reason: '坏等级' },
      { command: 'w', args: [], severity: 'high', reason: '缺 id' },
    ],
  })
  assert.equal(policy.customRules.length, 1)
  assert.ok(warnings.length >= 2)
})

test('load：用户文件 + 项目文件合并，项目优先', () => {
  const dir = tempDir()
  const userFile = path.join(dir, 'user.json')
  const projFile = path.join(dir, 'project.json')
  fs.writeFileSync(userFile, JSON.stringify({ level: 'vigilant', allowlist: ['git status'] }))
  fs.writeFileSync(projFile, JSON.stringify({ level: 'relaxed', allowlist: ['npm run'] }))
  const env = { ...process.env, BARRICADE_POLICY: userFile }
  const { policy, sources } = Policy.load({ env, cwd: dir, files: { project: projFile } })
  assert.equal(policy.level, 'relaxed')
  assert.deepEqual(policy.allowlist, ['npm run', 'git status'])
  assert.equal(sources.length, 2)
})

test('load：文件缺失不报错', () => {
  const env = { ...process.env, BARRICADE_POLICY: path.join(tempDir(), 'none.json') }
  const { policy, warnings } = Policy.load({ env, cwd: tempDir() })
  assert.equal(policy.level, 'balanced')
  assert.deepEqual(warnings, [])
})

test('load：损坏的 JSON 被挽救', () => {
  const dir = tempDir()
  const userFile = path.join(dir, 'bad.json')
  fs.writeFileSync(userFile, '{not json')
  const { policy, warnings } = Policy.load({ env: { ...process.env, BARRICADE_POLICY: userFile }, cwd: dir })
  assert.equal(policy.level, 'balanced')
  assert.ok(warnings.length > 0)
})

test('环境变量等级只能提升', () => {
  const p1 = Policy.load({ env: { ...process.env, BARRICADE_LEVEL: 'vigilant' }, cwd: tempDir(), files: {} }).policy
  assert.equal(p1.level, 'vigilant')
  const dir = tempDir()
  const file = path.join(dir, 'p.json')
  fs.writeFileSync(file, JSON.stringify({ level: 'vigilant' }))
  const p2 = Policy.load({ env: { ...process.env, BARRICADE_LEVEL: 'relaxed', BARRICADE_POLICY: file }, cwd: dir }).policy
  assert.equal(p2.level, 'vigilant')
})

test('appendOverride 写入用户策略文件并可重载', () => {
  const dir = tempDir()
  const file = path.join(dir, 'p.json')
  fs.writeFileSync(file, JSON.stringify({ level: 'balanced' }))
  const env = { ...process.env, BARRICADE_POLICY: file }
  const p = Policy.load({ env, cwd: dir }).policy
  const r = p.appendOverride('git/push-force', 'allow')
  assert.equal(r.ok, true)
  const again = Policy.load({ env, cwd: dir }).policy
  assert.equal(again.overrides['git/push-force'], 'allow')
})

test('checkAllowlist 前缀匹配', () => {
  const p = Policy.fromObject({ allowlist: ['git status', 'ls -la'] })
  assert.equal(p.checkAllowlist('git status'), true)
  assert.equal(p.checkAllowlist('git status --porcelain'), true)
  assert.equal(p.checkAllowlist('git push'), false)
  assert.equal(p.checkAllowlist('ls'), false)
})

test('BARRICADE_FAIL_CLOSED 环境变量生效', () => {
  const p = Policy.load({ env: { ...process.env, BARRICADE_FAIL_CLOSED: '1' }, cwd: tempDir(), files: {} }).policy
  assert.equal(p.failClosed, true)
})
