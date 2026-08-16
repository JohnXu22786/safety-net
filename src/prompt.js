// 交互式确认界面：展示命令与命中规则，等待用户选择。
// 非 TTY 环境下不询问，直接拒绝（失败安全）。

import readline from 'node:readline'
import { sanitizeForDisplay, paint, useColor } from './utils.js'

const KEYS_HINT = '[y] 执行一次  [n] 拒绝  [s] 本会话放行  [a] 永久放行  [d] 详情  [q] 退出'

/**
 * 对一条待确认条目发起交互确认。
 * @param {{command: string, severity: string, matches: Array}} entry
 * @param {{tty: boolean, input: any, output: any, policy: object, session: Set, timeoutMs: number}} opts
 * @returns {Promise<{decision: 'allow'|'deny'|'session'|'always'}>}
 */
export function confirmEntry(entry, opts) {
  return new Promise((resolve) => {
    const { tty, input, output, policy, session, timeoutMs = 0 } = opts
    if (!tty) {
      writeBlocked(output, entry)
      resolve({ decision: 'deny' })
      return
    }

    const color = useColor(output)
    const severity = entry.severity ?? 'high'
    const sevLabel = { critical: '致命', high: '高危', medium: '中危' }[severity] ?? severity

    const rl = readline.createInterface({ input, output, terminal: false })
    let timer = null
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        output.write('\n[barricade] 确认超时，按拒绝处理\n')
        rl.close()
        resolve({ decision: 'deny' })
      }, timeoutMs)
    }
    const finish = (decision) => {
      if (timer) clearTimeout(timer)
      resolve({ decision }) // 先决议再关闭，避免 close 事件的处理抢先覆盖
      rl.close()
    }
    // 输入流关闭（EOF/Ctrl+D）或 SIGINT 时按拒绝处理，避免无限挂起
    rl.on('close', () => finish('deny'))
    rl.on('SIGINT', () => finish('deny'))

    const detailText = () => {
      const lines = ['', '命中规则详情:']
      for (const m of entry.matches) {
        lines.push(`  • ${m.ruleId} [${m.severity}] ${m.message}`)
      }
      return lines.join('\n') + '\n'
    }

    const ask = () => {
      const title = paint(`⚠️  Barricade 需要确认此命令 [${sevLabel}]`, severity === 'medium' ? 'yellow' : 'red', color)
      output.write(`\n${title}\n命令: ${sanitizeForDisplay(entry.command)}\n`)
      for (const m of entry.matches.slice(0, 5)) {
        output.write(paint(`  • ${m.ruleId} — ${m.message}`, 'cyan', color) + '\n')
      }
      output.write(`${KEYS_HINT}\n> `)
      rl.question('', (ans) => {
        const key = ans.trim().toLowerCase()
        if (key === 'y') { finish('allow'); return }
        if (key === 'n' || key === 'q') { finish('deny'); return }
        if (key === 's') {
          for (const m of entry.matches) session.add(m.ruleId)
          output.write('已记录本会话放行规则\n')
          finish('session')
          return
        }
        if (key === 'a') {
          const nonCritical = entry.matches.filter((m) => m.severity !== 'critical')
          if (nonCritical.length === 0) {
            output.write('致命规则不可永久放行\n')
            ask()
            return
          }
          let ok = true
          for (const m of nonCritical) {
            const r = policy.appendOverride(m.ruleId, 'allow')
            if (!r.ok) ok = false
          }
          if (ok) {
            output.write(`已写入策略: ${nonCritical.map((m) => m.ruleId).join(', ')} → allow\n`)
            finish('always')
          } else {
            output.write('策略写入失败，已忽略\n')
            ask()
          }
          return
        }
        if (key === 'd') { output.write(detailText()); ask(); return }
        output.write('无效输入，请选择 y / n / s / a / d / q\n')
        ask()
      })
    }
    ask()
  })
}

function writeBlocked(output, entry) {
  output.write(`⛔ Barricade 已拦截该命令（${entry.severity ?? ''}），非交互环境不做自动放行\n`)
  output.write(`命令: ${sanitizeForDisplay(entry.command)}\n`)
  for (const m of entry.matches.slice(0, 5)) output.write(`  • ${m.ruleId} — ${m.message}\n`)
}
