// 判定结果模型：Verdict 与多命中合并逻辑

import { ACTION_BY_LEVEL, SEVERITY_LABEL, SEVERITY_RANK } from './rules.js'
import { sanitizeForDisplay } from './utils.js'

export class Verdict {
  /**
   * @param {string} command 被分析的原始命令
   * @param {{action?: string, severity?: string|null, matches?: Array, warnings?: string[], reason?: string|null}} opts
   */
  constructor(command, opts = {}) {
    this.command = command
    this.action = opts.action ?? 'allow'
    this.severity = opts.severity ?? null
    this.matches = opts.matches ?? []
    this.warnings = opts.warnings ?? []
    this.reason = opts.reason ?? null
  }

  static allow(command, opts = {}) {
    return new Verdict(command, opts)
  }

  get isBlocked() {
    return this.action !== 'allow'
  }

  /** 序列化为可跨进程传输的 JSON（hook 协议、CLI --json 共用） */
  toJSON() {
    return {
      command: this.command,
      action: this.action,
      severity: this.severity,
      reason: this.reason,
      matches: this.matches.map((m) => ({
        ruleId: m.ruleId,
        severity: m.severity,
        title: m.title,
        message: m.message,
      })),
      warnings: this.warnings,
    }
  }

  /** 面向用户/agent 的拦截说明文本 */
  format() {
    if (this.action === 'allow') return '放行'
    const label = SEVERITY_LABEL[this.severity] ?? ''
    const head = this.action === 'deny'
      ? '⛔ Barricade 拦截该命令'
      : '⛔ Barricade 要求人工确认该命令'
    const lines = [
      `${head}${label ? ' · ' + label : ''}`,
      '',
      '原因:',
      ...this.matches.map((m) => `  • ${m.ruleId} — ${sanitizeForDisplay(m.message)}`),
      '',
      `命令: ${sanitizeForDisplay(this.command)}`,
      '',
      '提示: 如确属必要，请在终端手动执行该命令（或调整策略后重试）',
    ]
    return lines.join('\n')
  }
}

/**
 * 将一组命中（可能来自多个命令段、多个规则）合并为最终判定。
 * 规则: 致命优先、任一 deny 则拒绝、任一 ask 则确认、否则放行；
 * 策略 overrides 可调整高/中危动作，但致命规则不可降级。
 */
export function combineMatches(command, matches, warnings = [], policy) {
  const map = ACTION_BY_LEVEL[policy.level] ?? ACTION_BY_LEVEL.balanced
  const kept = []
  const warns = [...warnings]
  let denied = false
  let asked = false
  let worst = null

  for (const m of matches) {
    const override = policy.overrides[m.ruleId]
    let action = map[m.severity] ?? 'ask'
    if (override === 'deny') action = 'deny'
    else if (override === 'ask') action = 'ask'
    else if (override === 'allow' || override === 'off') action = 'allow'

    if (m.severity === 'critical' && action !== 'deny') {
      warns.push(`规则 ${m.ruleId} 为致命规则，无法降级为放行，仍按拒绝处理`)
      action = 'deny'
    }
    if (action === 'allow') continue

    kept.push({ ...m, action })
    if (action === 'deny') denied = true
    if (action === 'ask') asked = true
    if (!worst || SEVERITY_RANK[m.severity] > SEVERITY_RANK[worst.severity]) worst = m
  }

  if (denied) return new Verdict(command, { action: 'deny', severity: worst.severity, matches: kept, warnings: warns, reason: worst.message })
  if (asked) return new Verdict(command, { action: 'ask', severity: worst.severity, matches: kept, warnings: warns, reason: worst.message })
  return new Verdict(command, { action: 'allow', matches: [], warnings: warns })
}
