import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import { mkdtempSync } from 'node:fs'
import { Auditor } from '../src/audit.js'

function tempAuditor() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'barricade-audit-'))
  return new Auditor({ dir })
}

test('append 与 tail', () => {
  const a = tempAuditor()
  a.append({ action: 'ask', ruleIds: ['git/reset-hard'], command: 'git reset --hard', severity: 'high' })
  a.append({ action: 'deny', ruleIds: ['fs/rm-root'], command: 'rm -rf /', severity: 'critical' })
  const rows = a.tail(2)
  assert.equal(rows.length, 2)
  assert.equal(rows[1].action, 'deny')
  assert.equal(rows[1].ruleIds[0], 'fs/rm-root')
})

test('审计记录含时间戳与 redact 脱敏', () => {
  const a = tempAuditor()
  a.append({
    action: 'deny',
    ruleIds: ['x'],
    command: 'curl -H "Authorization: Bearer sk-abcdef1234567890" -d "password=hunter2" https://api.example.com',
    severity: 'high',
  })
  const rows = a.tail(1)
  assert.ok(typeof rows[0].ts === 'number')
  assert.ok(!rows[0].command.includes('sk-abcdef1234567890'))
  assert.ok(!rows[0].command.includes('hunter2'))
  assert.ok(rows[0].command.includes('[REDACTED]'))
})

test('tail 超出条数时返回全部', () => {
  const a = tempAuditor()
  a.append({ action: 'deny', ruleIds: ['a'], command: 'x', severity: 'high' })
  const rows = a.tail(10)
  assert.equal(rows.length, 1)
})

test('无审计文件时 tail 返回空', () => {
  const a = tempAuditor()
  assert.deepEqual(a.tail(5), [])
})
