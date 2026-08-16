// 审计日志：JSONL 追加写入，命令内容先脱敏。

import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { redact } from './utils.js'

export class Auditor {
  /**
   * @param {{dir: string}} opts 日志目录
   */
  constructor({ dir } = {}) {
    this.dir = dir || path.join(os.homedir(), '.barricade')
  }

  static fromEnv(env = process.env) {
    return new Auditor({ dir: env.BARRICADE_HOME || path.join(os.homedir(), '.barricade') })
  }

  get file() {
    return path.join(this.dir, 'audit.jsonl')
  }

  /** 追加一条审计记录（自动脱敏 command 并补时间戳） */
  append(record) {
    const row = {
      ts: typeof record.ts === 'number' ? record.ts : Date.now(),
      action: record.action ?? 'unknown',
      severity: record.severity ?? null,
      ruleIds: Array.isArray(record.ruleIds) ? record.ruleIds : [],
      command: redact(record.command ?? ''),
      cwd: record.cwd ?? null,
    }
    try {
      fs.mkdirSync(this.dir, { recursive: true })
      fs.appendFileSync(this.file, JSON.stringify(row) + '\n', 'utf8')
      return true
    } catch {
      return false
    }
  }

  /** 读取最近 n 条记录（n<=0 时返回空） */
  tail(n = 20) {
    if (n <= 0) return []
    let text
    try {
      text = fs.readFileSync(this.file, 'utf8')
    } catch {
      return []
    }
    const lines = text.split('\n').filter((l) => l.trim() !== '')
    const rows = []
    for (const line of lines.slice(-n)) {
      try {
        rows.push(JSON.parse(line))
      } catch {
        // 跳过损坏行
      }
    }
    return rows
  }
}
