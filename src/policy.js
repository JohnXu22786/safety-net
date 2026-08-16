// 策略配置：加载、校验（挽救式）、合并与环境变量。
// 配置文件格式为 JSON，字段缺失或类型错误时回退默认值并给出警告，绝不因此崩溃。

import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { LEVEL_ORDER, LEVELS } from './rules.js'

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium'])
const VALID_ACTIONS = new Set(['allow', 'ask', 'deny', 'off'])
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/

export function defaultPolicy() {
  return {
    level: 'balanced',
    failClosed: false,
    allowlist: [],
    overrides: {},
    customRules: [],
    confirmation: { sessionMemory: true, timeoutSeconds: 0 },
  }
}

export class Policy {
  /**
   * @param {object} cfg 字段同 defaultPolicy()
   * @param {{sources?: string[], files?: object, warnings?: string[]}} meta
   */
  constructor(cfg = {}, meta = {}) {
    this.level = cfg.level ?? 'balanced'
    this.failClosed = Boolean(cfg.failClosed)
    this.allowlist = [...(cfg.allowlist ?? [])]
    this.overrides = { ...(cfg.overrides ?? {}) }
    this.customRules = [...(cfg.customRules ?? [])]
    this.confirmation = { ...defaultPolicy().confirmation, ...(cfg.confirmation ?? {}) }
    this.sources = [...(meta.sources ?? [])]
    this.files = { ...(meta.files ?? {}) }
    this.warnings = [...(meta.warnings ?? [])]
  }

  /** 解析一个策略对象（含挽救式校验），返回实例 */
  static fromObject(obj = {}) {
    const { policy } = Policy.parse(obj)
    return policy
  }

  /** 解析一个策略对象，返回 { policy, warnings } */
  static parse(obj = {}) {
    const warnings = []
    const out = defaultPolicy()
    if (typeof obj !== 'object' || obj === null) {
      warnings.push('策略内容不是对象，使用默认策略')
      return { policy: new Policy(out), warnings }
    }
    if (obj.level !== undefined) {
      if (LEVELS.includes(obj.level)) out.level = obj.level
      else warnings.push(`未知等级 "${obj.level}"，回退为 balanced`)
    }
    if (obj.failClosed !== undefined) {
      if (typeof obj.failClosed === 'boolean') out.failClosed = obj.failClosed
      else warnings.push('failClosed 应为布尔值，回退为 false')
    }
    if (obj.allowlist !== undefined) {
      if (Array.isArray(obj.allowlist)) out.allowlist = obj.allowlist.filter((x) => typeof x === 'string')
      else warnings.push('allowlist 应为字符串数组，回退为空')
    }
    if (obj.overrides !== undefined) {
      if (typeof obj.overrides === 'object' && obj.overrides !== null) {
        for (const [id, action] of Object.entries(obj.overrides)) {
          if (VALID_ACTIONS.has(action)) out.overrides[id] = action
          else warnings.push(`override ${id} 的动作 "${action}" 无效，已忽略`)
        }
      } else warnings.push('overrides 应为对象，回退为空')
    }
    if (obj.rules !== undefined) {
      if (Array.isArray(obj.rules)) {
        const seen = new Set()
        for (const r of obj.rules) {
          if (typeof r !== 'object' || r === null) { warnings.push('存在无效自定义规则条目'); continue }
          if (typeof r.id !== 'string' || !r.id.trim()) { warnings.push('自定义规则缺少有效 id，已丢弃'); continue }
          if (seen.has(r.id)) { warnings.push(`自定义规则 id 重复: ${r.id}，已丢弃`); continue }
          if (typeof r.command !== 'string' || !r.command.trim()) { warnings.push(`规则 ${r.id} 缺少 command，已丢弃`); continue }
          if (!VALID_SEVERITIES.has(r.severity)) { warnings.push(`规则 ${r.id} 的 severity 无效，已丢弃`); continue }
          const args = Array.isArray(r.args) ? r.args.filter((x) => typeof x === 'string') : []
          seen.add(r.id)
          out.customRules.push({
            id: r.id,
            command: r.command,
            subcommand: typeof r.subcommand === 'string' ? r.subcommand : null,
            args,
            severity: r.severity,
            reason: typeof r.reason === 'string' ? r.reason : r.id,
          })
        }
      } else warnings.push('rules 应为数组，回退为空')
    }
    if (obj.confirmation !== undefined && typeof obj.confirmation === 'object' && obj.confirmation !== null) {
      if (typeof obj.confirmation.sessionMemory === 'boolean') out.confirmation.sessionMemory = obj.confirmation.sessionMemory
      if (typeof obj.confirmation.timeoutSeconds === 'number' && obj.confirmation.timeoutSeconds >= 0) {
        out.confirmation.timeoutSeconds = obj.confirmation.timeoutSeconds
      }
    }
    return { policy: new Policy(out), warnings }
  }

  /**
   * 从文件与环境加载策略。顺序：默认 ← 用户文件 ← 项目文件 ← 环境变量（只升不降）。
   * @returns {{policy: Policy, warnings: string[], sources: string[]}}
   */
  static load({ env = process.env, cwd = process.cwd(), files = null } = {}) {
    const home = env.BARRICADE_HOME || path.join(os.homedir(), '.barricade')
    const userFile = files?.user ?? (env.BARRICADE_POLICY || path.join(home, 'barricade.json'))
    const projectFile = files?.project ?? path.join(cwd, '.barricade.json')
    const warnings = []
    const sources = []

    const readFile = (file) => {
      let obj = null
      try {
        const text = fs.readFileSync(file, 'utf8')
        obj = JSON.parse(text)
        sources.push(file)
      } catch (e) {
        if (e.code !== 'ENOENT') warnings.push(`策略文件 ${file} 解析失败: ${e.message}，已跳过`)
      }
      return obj
    }

    let policy = new Policy(defaultPolicy(), { files: { user: userFile, project: projectFile, home } })
    const userObj = readFile(userFile)
    if (userObj) {
      const r = Policy.parse(userObj)
      policy = mergePolicies(policy, r.policy)
      warnings.push(...r.warnings)
    }
    const projObj = readFile(projectFile)
    if (projObj && projectFile !== userFile) {
      const r = Policy.parse(projObj)
      policy = mergePolicies(policy, r.policy, { project: true })
      warnings.push(...r.warnings)
    }

    // 环境变量：只允许提升
    if (env.BARRICADE_LEVEL && LEVELS.includes(env.BARRICADE_LEVEL)) {
      if (LEVEL_ORDER[env.BARRICADE_LEVEL] > LEVEL_ORDER[policy.level]) policy.level = env.BARRICADE_LEVEL
    }
    if (env.BARRICADE_FAIL_CLOSED === '1') policy.failClosed = true
    if (env.BARRICADE_CONFIRM_TIMEOUT && !Number.isNaN(Number(env.BARRICADE_CONFIRM_TIMEOUT))) {
      policy.confirmation.timeoutSeconds = Math.max(0, Number(env.BARRICADE_CONFIRM_TIMEOUT))
    }

    policy.sources = sources
    policy.warnings = warnings
    return { policy, warnings, sources }
  }

  /** 生成等级被提升后的新实例（共享其余字段） */
  withLevel(level) {
    return new Policy({ ...this, level, confirmation: { ...this.confirmation } }, { sources: this.sources, files: this.files })
  }

  /** allowlist 前缀命中检查（命令与条目按空格规范化） */
  checkAllowlist(command) {
    const cmd = String(command).trim()
    if (!cmd) return false
    return this.allowlist.some((entry) => {
      const e = String(entry).trim()
      return e !== '' && (cmd === e || cmd.startsWith(e + ' '))
    })
  }

  /** 向用户策略文件写入一条 override（供交互确认的“永久放行”使用） */
  appendOverride(ruleId, action) {
    const file = this.files.user
    if (!file) return { ok: false, error: '未配置用户策略文件路径' }
    let obj = {}
    try {
      obj = JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch {
      obj = {}
    }
    if (typeof obj !== 'object' || obj === null) obj = {}
    obj.overrides = { ...(obj.overrides ?? {}), [ruleId]: action }
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true })
      fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8')
      return { ok: true }
    } catch (e) {
      return { ok: false, error: String(e.message) }
    }
  }

  /** 序列化（用于 policy --show） */
  toJSON() {
    return {
      version: 1,
      level: this.level,
      failClosed: this.failClosed,
      allowlist: this.allowlist,
      overrides: this.overrides,
      rules: this.customRules,
      confirmation: this.confirmation,
    }
  }
}

/** 合并两份策略：later 覆盖 earlier（项目文件优先于用户文件） */
function mergePolicies(base, extra, { project = false } = {}) {
  return new Policy(
    {
      level: extra.level,
      failClosed: extra.failClosed || base.failClosed,
      allowlist: project ? [...extra.allowlist, ...base.allowlist] : [...base.allowlist, ...extra.allowlist],
      overrides: { ...base.overrides, ...extra.overrides },
      customRules: [...extra.customRules, ...base.customRules.filter((r) => !extra.customRules.some((x) => x.id === r.id))],
      confirmation: { ...base.confirmation, ...extra.confirmation },
    },
    { files: { ...base.files }, warnings: [...base.warnings, ...extra.warnings] },
  )
}

export { ASSIGNMENT_RE }
