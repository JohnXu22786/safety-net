import test from 'node:test'
import assert from 'node:assert/strict'
import { combineMatches, Verdict } from '../src/verdict.js'
import { Policy } from '../src/policy.js'

function policy(obj = {}) {
  return Policy.fromObject(obj)
}

test('无命中 → 放行', () => {
  const v = combineMatches('ls', [], [], policy())
  assert.equal(v.action, 'allow')
  assert.equal(v.isBlocked, false)
})

test('单个高危命中 → ask', () => {
  const v = combineMatches('git push --force', [{ ruleId: 'git/push-force', severity: 'high', message: 'x' }], [], policy())
  assert.equal(v.action, 'ask')
  assert.equal(v.isBlocked, true)
})

test('致命命中 → deny，且不因 overrides 降级', () => {
  const v = combineMatches(
    'rm -rf /',
    [{ ruleId: 'fs/rm-root', severity: 'critical', message: 'x' }],
    [],
    policy({ overrides: { 'fs/rm-root': 'allow' } }),
  )
  assert.equal(v.action, 'deny')
})

test('多命中取最严', () => {
  const v = combineMatches(
    'x',
    [
      { ruleId: 'a/medium', severity: 'medium', message: 'm' },
      { ruleId: 'a/high', severity: 'high', message: 'h' },
    ],
    [],
    policy(),
  )
  assert.equal(v.action, 'ask')
  assert.equal(v.severity, 'high')
})

test('overrides 可把高危降为放行（off）', () => {
  const v = combineMatches(
    'x',
    [{ ruleId: 'git/reset-hard', severity: 'high', message: 'm' }],
    [],
    policy({ overrides: { 'git/reset-hard': 'allow' } }),
  )
  assert.equal(v.action, 'allow')
  assert.equal(v.matches.length, 0)
})

test('relaxed 等级下中危 → 放行', () => {
  const v = combineMatches('x', [{ ruleId: 'git/tag-delete', severity: 'medium', message: 'm' }], [], policy({ level: 'relaxed' }))
  assert.equal(v.action, 'allow')
})

test('Verdict.allow 工厂与 toJSON 形状', () => {
  const v = Verdict.allow('ls', { warnings: ['w'] })
  const j = v.toJSON()
  assert.equal(j.action, 'allow')
  assert.equal(j.command, 'ls')
  assert.deepEqual(j.matches, [])
  assert.deepEqual(j.warnings, ['w'])
})

test('format 包含规则 id、命令与建议', () => {
  const v = combineMatches(
    'rm -rf /',
    [{ ruleId: 'fs/rm-root', severity: 'critical', message: '删除根目录' }],
    [],
    policy(),
  )
  const text = v.format()
  assert.ok(text.includes('fs/rm-root'))
  assert.ok(text.includes('rm -rf /'))
  assert.ok(text.includes('删除根目录'))
})
