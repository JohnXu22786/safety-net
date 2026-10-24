// Barricade 的 dsh（DeepSeek Harness / Cordis）插件入口。
// 接入方式:
//   - package.json 声明 dsh.bundle + cordis.patch.yml（本仓库已带）
//   - 安装后 Cordis 加载本模块（main 指向本文件），调用 apply(ctx, config)
// 行为: 监听工具执行管线事件 tools/pre-execute，拦截 shell 类工具中的破坏性命令。
//   mode=deny 时直接返回拒绝决策（工具调用失败，模型可见原因）；
//   mode=ask  时返回询问决策，交给 harness 的 approval 通道请求人工确认；
//             无 approval 通道或用户拒绝时按拒绝处理（失败安全）。
//
// host 契约（0.1.1 修正）:
//   1) tools/pre-execute 是 cordis 的 **waterfall** 事件：
//      监听器签名 (exec, next) => Promise<Decision>，Decision 为
//        { kind: 'allow' } | { kind: 'deny', reason, info? } | { kind: 'ask', reason?, displayReason? } | { kind: 'cancel' }
//      返回 deny/ask 即否决本次调用；放行必须 return next()（不调用 next 会截断整条链）。
//      抛异常不是拒绝途径——它会让本次调用以 toolErrorResult 收尾。
//   2) exec 结构（@deepseek-ai/dsh-tools createExecution）:
//      { token, callId, rootCallId, name, signal, agent?, parent?, schema?, arguments: <冻结副本> }
//      即工具参数在 exec.arguments 下（bash/pwsh 为 arguments.command），**不是** args.command。
//   3) 读服务必须走 ctx.get(name)：cordis 的 ctx Proxy 对未在 inject 中声明的属性会直接抛
//      "cannot get property \"x\" without inject"，ctx.get 是官方的不抛错读法。
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

/** 参数是代码体而非 shell 命令的工具；必须使用独立的 fail-closed 策略。 */
export const CODE_TOOLS = ['run_code']

/** 自动探测命令字段的候选路径（按序；配置了 commandPath 时只用配置值）。 */
const COMMAND_PATHS = ['arguments.command', 'args.command', 'input.command', 'command']

/** 供其他 harness 进程内复用: 纯判定逻辑，不依赖 dsh 上下文。
 * 返回一个可调用函数（intercept），同时携带 .config 便于自省。
 */
export function createInterceptor(config = {}, env = process.env) {
  const configured = env.BARRICADE_TOOLS || (Array.isArray(config.toolNames) ? config.toolNames.join(',') : null)
  // BARRICADE_TOOLS 为空白等非法值时回退默认名单，避免静默禁用拦截
  const parsed = configured ? configured.split(',').map((s) => s.trim()).filter(Boolean) : null
  const toolNames = parsed && parsed.length > 0 ? parsed : DEFAULT_TOOLS

  /** 判定一次工具调用。返回 {action:'allow'} 或
   *  {action:'block', reason, verdict:'deny'|'ask'}（verdict 供宿主区分"直接拒绝"与"转人工确认"）。 */
  const intercept = async (call) => {
    if (!call || typeof call !== 'object') return { action: 'allow' }
    const tool = call.name ?? call.tool ?? call.toolName
    if (typeof tool !== 'string' || !toolNames.includes(tool)) return { action: 'allow' }
    const codeTool = CODE_TOOLS.includes(tool)
    if (codeTool) {
      const code = resolveCode(call)
      if (typeof code !== 'string' || !code.trim()) {
        return {
          action: 'block',
          verdict: 'deny',
          reason: 'Barricade: run_code 缺少非空字符串 code，已拒绝执行',
        }
      }
      const verdict = createCodeVerdict(code)
      if (mode === 'ask') {
        // 任意 JavaScript 都不可由 shell 分析器安全验证，只能经过显式 approval。
        if (approval) {
          const approved = await requestApproval(approval, verdict, true)
          if (approved) return { action: 'allow', confirmed: true }
          return { action: 'block', verdict: 'deny', reason: verdict.format() }
        }
        return { action: 'block', verdict: 'ask', reason: verdict.format() }
      }
      return { action: 'block', verdict: 'deny', reason: verdict.format() }
    }

    const command = resolveCommand(call, commandPath, COMMAND_PATHS)
    if (typeof command !== 'string' || !command.trim()) {
      return {
        action: 'block',
        verdict: 'deny',
        reason: 'Barricade: 工具调用缺少字符串形式的命令字段，已拒绝执行',
      }
    }
    // 工具调用自带 cwd 时优先使用；声称的工作目录越出真实工作区时忽略（防降级绕过）
    const realCwd = process.cwd()
    let callCwd = typeof call.arguments?.workdir === 'string' ? call.arguments.workdir
      : typeof call.arguments?.cwd === 'string' ? call.arguments.cwd
        : typeof call.args?.cwd === 'string' ? call.args.cwd
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
      // 显式注入的 approval（独立使用/测试）就地确认；否则把询问交给宿主 waterfall 决策
      if (approval) {
        const approved = await requestApproval(approval, verdict)
        if (approved) return { action: 'allow', confirmed: true }
        return { action: 'block', verdict: 'deny', reason: verdict.format() }
      }
      return { action: 'block', verdict: 'ask', reason: verdict.format() }
    }
    return { action: 'block', verdict: 'deny', reason: verdict.format() }
  }

  const mode = config.mode ?? 'deny'
  const commandPath = typeof config.commandPath === 'string' && config.commandPath ? config.commandPath : null
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

/** 解析本次调用携带的命令文本；配置了 commandPath 时以其为准，否则按候选路径自动探测。 */
function resolveCommand(call, configured, candidates) {
  if (configured) return getByPath(call, configured)
  for (const p of candidates) {
    const v = getByPath(call, p)
    if (typeof v === 'string' && v.trim()) return v
  }
  // 兜底：一层浅扫描，兼容 { command } / { input: { command } } / { code } 之外的宿主形态
  for (const key of ['arguments', 'args', 'input', 'parameters']) {
    const box = call[key]
    if (!box || typeof box !== 'object') continue
    for (const field of ['command', 'cmd', 'script', 'code']) {
      const v = box[field]
      if (typeof v === 'string' && v.trim()) return v
    }
  }
  return undefined
}

/** 只读取已知 code 字段，避免将 run_code 参数当作 shell 命令兜底解析。 */
function resolveCode(call) {
  for (const box of [call.arguments, call.args, call.input, call]) {
    if (box && typeof box === 'object' && box.code !== undefined) return box.code
  }
  return undefined
}

function createCodeVerdict(code) {
  const reason = 'Barricade: run_code 的 JavaScript 无法由 shell 分析器验证，需显式批准'
  return {
    format: () => reason,
    toJSON: () => ({ action: 'ask', tool: 'run_code', code, reason }),
  }
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

/** 不抛错地读取 cordis 服务（ctx Proxy 对未 inject 的属性会抛错，ctx.get 是官方安全读法）。 */
export function readService(ctx, service) {
  if (!ctx || typeof ctx.get !== 'function') return undefined
  try {
    return ctx.get(service)
  } catch {
    return undefined
  }
}

/**
 * 向 approval 服务发起确认请求。
 * dsh 的 approval 接口处于演进中，这里对多种形态做防御式探测；
 * 任何形态都不可用时返回 false（拒绝）。
 */
async function requestApproval(approval, verdict, requireExplicit = false) {
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
      return interpretApproval(r, requireExplicit)
    } catch {
      // 尝试下一种形态
    }
  }
  return false
}

function interpretApproval(r, requireExplicit = false) {
  const explicitlyApproved = (value) =>
    /^(allow|allowed|allow-once|allowed-once|approve|approved|yes)$/i.test(String(value))
  if (typeof r === 'boolean') return r
  if (typeof r === 'string') return requireExplicit ? explicitlyApproved(r) : !/^(deny|reject|refuse|no)/i.test(r)
  if (r && typeof r === 'object') {
    if (typeof r.approved === 'boolean') return r.approved
    if (typeof r.allowed === 'boolean') return r.allowed
    if (r.decision !== undefined) return requireExplicit ? explicitlyApproved(r.decision) : r.decision !== 'deny' && r.decision !== 'reject'
    if (r.status !== undefined) return requireExplicit ? explicitlyApproved(r.status) : !/^(deny|reject|refused)$/i.test(String(r.status))
  }
  return false
}

/**
 * Cordis 插件入口。
 * 注册 tools/pre-execute waterfall 监听：安全放行（return next()），危险则返回拒绝/询问决策。
 */
export function apply(ctx, config = {}) {
  const approvalService = readService(ctx, 'approval')
  const interceptor = createInterceptor({ ...config })

  ctx.on('tools/pre-execute', async (exec, next) => {
    let result
    try {
      result = await interceptor(exec)
    } catch (error) {
      // 判定过程自身异常：失败安全拒绝，且不截断在异常里
      return {
        kind: 'deny',
        reason: 'Barricade: 判定过程异常，已按拒绝处理 — ' + describeError(error),
      }
    }
    if (!result || result.action !== 'block') return await next()
    const reason = result.reason ?? '⛔ Barricade 拦截该命令'
    if (result.verdict === 'ask') {
      if (approvalService !== undefined && approvalService !== null) {
        return { kind: 'ask', reason }
      }
      return {
        kind: 'deny',
        reason: reason + '\n\n（本环境没有可用的 approval 通道，按拒绝处理）',
      }
    }
    return { kind: 'deny', reason }
  })
}

function describeError(error) {
  if (!error) return String(error)
  return error instanceof Error ? (error.message || error.name) : String(error)
}
