// Barricade 的 dsh（DeepSeek Harness / Cordis）插件入口。
// 接入方式:
//   - package.json 声明 dsh.bundle + cordis.patch.yml（本仓库已带）
//   - 安装后 Cordis 加载本模块（main 指向本文件），调用 apply(ctx, config)
// 行为: 监听工具执行管线事件 tools/pre-execute，拦截 shell 类工具中的破坏性命令。
//   mode=deny 时直接抛出拦截错误（工具调用失败，模型可见原因）；
//   mode=ask  时先经 ctx.approval 服务请求人工确认，确认被拒或服务不可用时
//             按拒绝处理（失败安全）。
import os from 'node:os'
import path from 'node:path'
import { analyzeCommand } from './src/analyzer.js'
import { Policy } from './src/policy.js'
import { LEVELS } from './src/rules.js'

export const name = 'barricade'

/** 依赖的工具注册表服务（等待其就绪后再挂接事件） */
export const inject = ['tools']

export const DEFAULT_TOOLS = [
  'bash', 'sh', 'zsh', 'shell', 'terminal', 'run_command', 'run_code',
  'command', 'cmd', 'powershell', 'pwsh', 'exec',
]

/** 供其他 harness 进程内复用: 纯判定逻辑，不依赖 dsh 上下文。
 * 返回一个可调用函数（intercept），同时携带 .config 便于自省。
 */
export function createInterceptor(config = {}, env = process.env) {
  const configured = env.BARRICADE_TOOLS || (Array.isArray(config.toolNames) ? config.toolNames.join(',') : null)
  // BARRICADE_TOOLS 为空白等非法值时回退默认名单，避免静默禁用拦截
  const parsed = configured ? configured.split(',').map((s) => s.trim()).filter(Boolean) : null
  const toolNames = parsed && parsed.length > 0 ? parsed : DEFAULT_TOOLS

  /** 判定一次工具调用。返回 {action:'allow'} 或 {action:'block', reason} */
  const intercept = async (call) => {
    if (!call || typeof call !== 'object') return { action: 'allow' }
    const tool = call.name ?? call.tool ?? call.toolName
    if (typeof tool !== 'string' || !toolNames.includes(tool)) return { action: 'allow' }
    const command = getByPath(call, commandPath)
    if (typeof command !== 'string' || !command.trim()) {
      // 命令字段缺失/类型异常：失败安全拒绝
      return { action: 'block', reason: 'Barricade: 工具调用缺少字符串形式的命令字段，已拒绝执行' }
    }
    // 工具调用自带 cwd 时优先使用；声称的工作目录越出真实工作区时忽略（防降级绕过）
    const realCwd = process.cwd()
    let callCwd = typeof call.args?.cwd === 'string' ? call.args.cwd
      : typeof call.cwd === 'string' ? call.cwd
        : null
    if (callCwd) {
      const rel = path.relative(realCwd, callCwd)
      if (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) callCwd = null
    }
    const verdict = analyzeCommand(command, {
      policy,
      cwd: callCwd ?? realCwd,
      home: os.homedir(),
      env,
    })
    if (verdict.action === 'allow') return { action: 'allow' }
    if (mode === 'ask') {
      const approved = await requestApproval(approval, verdict)
      if (approved) return { action: 'allow', confirmed: true }
      return { action: 'block', reason: verdict.format() }
    }
    return { action: 'block', reason: verdict.format() }
  }

  const mode = config.mode ?? 'deny'
  const commandPath = config.commandPath ?? 'args.command'
  const approval = config.approval
  const policy = (() => {
    let p = config.policy ?? Policy.load({ env, cwd: process.cwd() }).policy
    if (config.level && LEVELS.includes(config.level)) p = p.withLevel(config.level)
    return p
  })()

  const interceptor = Object.assign(intercept, {
    config: { toolNames, commandPath, mode, approval, level: config.level, policy },
  })
  return interceptor
}

/** 按点路径取值（args.command / input.command / command），并兜底顶层 command 键 */
function getByPath(obj, dotPath) {
  const parts = String(dotPath).split('.')
  let cur = obj
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined
    cur = cur[p]
  }
  if (cur === undefined && dotPath !== 'command') return obj.command
  return cur
}

/**
 * 向 approval 服务发起确认请求。
 * dsh 的 approval 接口处于演进中，这里对多种形态做防御式探测；
 * 任何形态都不可用时返回 false（拒绝）。
 */
async function requestApproval(approval, verdict) {
  if (!approval) return false
  for (const fnName of ['ask', 'request', 'create', 'prompt']) {
    const fn = approval[fnName]
    if (typeof fn !== 'function') continue
    try {
      const r = await fn.call(approval, {
        kind: 'barricade-confirm',
        title: 'Barricade 危险命令确认',
        detail: verdict.format(),
        payload: verdict.toJSON(),
      })
      return interpretApproval(r)
    } catch {
      // 尝试下一种形态
    }
  }
  return false
}

function interpretApproval(r) {
  if (typeof r === 'boolean') return r
  if (typeof r === 'string') return !/^(deny|reject|refuse|no)/i.test(r)
  if (r && typeof r === 'object') {
    if (typeof r.approved === 'boolean') return r.approved
    if (typeof r.allowed === 'boolean') return r.allowed
    if (r.decision !== undefined) return r.decision !== 'deny' && r.decision !== 'reject'
    if (r.status !== undefined) return !/^(deny|reject|refused)$/i.test(String(r.status))
  }
  return false
}

/** Cordis 插件入口 */
export function apply(ctx, config = {}) {
  const interceptor = createInterceptor({ ...config, approval: ctx.approval ?? config.approval })
  ctx.on('tools/pre-execute', async (call) => {
    const result = await interceptor(call)
    if (result.action === 'block') {
      const err = new Error(result.reason)
      err.name = 'BarricadeBlocked'
      throw err
    }
    return call
  })
}
