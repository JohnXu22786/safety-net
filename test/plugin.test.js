import test from 'node:test'
import assert from 'node:assert/strict'
import { createInterceptor, apply, name } from '../plugin.js'

test('插件名称与声明', () => {
  assert.equal(name, 'barricade')
})

test('拦截器：默认工具列表 + 默认命令字段', async () => {
  const interceptor = createInterceptor({})
  const r1 = await interceptor({ name: 'bash', args: { command: 'ls' } })
  assert.equal(r1.action, 'allow')
  const r2 = await interceptor({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r2.action, 'block')
  assert.ok(r2.reason.includes('fs/rm-root'))
})

test('拦截器：非 shell 工具不处理', async () => {
  const interceptor = createInterceptor({})
  const r = await interceptor({ name: 'str_replace_editor', args: { path: '/a.txt', old: 'x', new: 'y' } })
  assert.equal(r.action, 'allow')
})

test('拦截器：命令字段可配置（点路径）', async () => {
  const interceptor = createInterceptor({ commandPath: 'input.command' })
  const r = await interceptor({ name: 'bash', input: { command: 'rm -rf /' } })
  assert.equal(r.action, 'block')
})

test('拦截器：工具名单可配置', async () => {
  const interceptor = createInterceptor({ toolNames: ['run_code'] })
  const r = await interceptor({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r.action, 'allow')
  const r2 = await interceptor({ name: 'run_code', args: { command: 'rm -rf /' } })
  assert.equal(r2.action, 'block')
})

test('拦截器：BARRICADE_TOOLS 环境变量覆盖工具名单', () => {
  const interceptor = createInterceptor({}, { BARRICADE_TOOLS: 'sh,run' })
  assert.deepEqual(interceptor.config.toolNames, ['sh', 'run'])
})

test('拦截器：ask 模式经 approval 服务确认', async () => {
  const allowed = createInterceptor({ mode: 'ask', approval: { ask: async () => true } })
  const r1 = await allowed({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r1.action, 'allow')
  const denied = createInterceptor({ mode: 'ask', approval: { ask: async () => false } })
  const r2 = await denied({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r2.action, 'block')
})

test('拦截器：ask 模式但 approval 不可用 → 失败安全拒绝', async () => {
  const interceptor = createInterceptor({ mode: 'ask', approval: undefined })
  const r = await interceptor({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r.action, 'block')
})

test('拦截器：异常输入不崩溃（缺失命令字段按拒绝处理）', async () => {
  const interceptor = createInterceptor({})
  assert.equal((await interceptor(null)).action, 'allow')
  assert.equal((await interceptor({})).action, 'allow')
  // 命令字段缺失或类型异常：失败安全拒绝（防协议违约绕过）
  assert.equal((await interceptor({ name: 'bash', args: { command: 42 } })).action, 'block')
  assert.equal((await interceptor({ name: 'bash', args: {} })).action, 'block')
  assert.equal((await interceptor({ name: 'bash', args: { command: '' } })).action, 'block')
})

test('拦截器：BARRICADE_TOOLS 为空白时回退默认名单', () => {
  const a = createInterceptor({}, { BARRICADE_TOOLS: ' , ' })
  assert.deepEqual(a.config.toolNames, ['bash', 'sh', 'zsh', 'shell', 'terminal', 'run_command', 'run_code', 'command', 'cmd', 'powershell', 'pwsh', 'exec'])
})

test('拦截器：声称的工作目录越出真实工作区时被忽略', async () => {
  // relaxed 下：若 cwd 声称 '/' 被采纳，rm -rf /etc/foo 会被判为工作区内（中危→放行）
  const interceptor = createInterceptor({ mode: 'deny', level: 'relaxed' })
  const r = await interceptor({ name: 'bash', args: { command: 'rm -rf /etc/foo', cwd: '/' } })
  assert.equal(r.action, 'block')
})

test('拦截器：工作区位于用户主目录内时配置 level 生效', async () => {
  const relaxed = createInterceptor({ level: 'relaxed' })
  // checkout 位于 home 下时，工作区内目标仍属中危，relaxed 应放行
  const r = await relaxed({ name: 'bash', args: { command: 'rm -rf ./dist' } })
  assert.equal(r.action, 'allow')
  const vigilant = createInterceptor({ level: 'vigilant' })
  const r2 = await vigilant({ name: 'bash', args: { command: 'rm -rf ./dist' } })
  assert.equal(r2.action, 'block')
  assert.ok(r2.reason.includes('fs/rm-workspace'))
})

test('apply：注册 tools/pre-execute waterfall 监听并拦截破坏性调用', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
    get() {
      return undefined
    },
  }
  apply(ctx, {})
  assert.ok(typeof handlers['tools/pre-execute'] === 'function')
  const handler = handlers['tools/pre-execute']
  const next = async () => ({ kind: 'allow' })
  // 安全调用：放行，且必须向下游放行（调用 next）
  const safe = await handler({ name: 'bash', arguments: { command: 'git status' } }, next)
  assert.equal(safe.kind, 'allow')
  // 破坏性调用：返回 deny 决策（不再抛错），原因里带规则号
  const blocked = await handler({ name: 'bash', arguments: { command: 'rm -rf /' } }, next)
  assert.equal(blocked.kind, 'deny')
  assert.ok(blocked.reason.includes('fs/rm-root'))
})

test('apply：ask 模式无 approval 通道时降级为 deny', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
    get() {
      return undefined
    },
  }
  apply(ctx, { mode: 'ask' })
  const r = await handlers['tools/pre-execute'](
    { name: 'bash', arguments: { command: 'rm -rf /' } },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(r.kind, 'deny')
})

test('apply：ask 模式有 approval 通道时返回 ask 决策', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
    get(name) {
      return name === 'approval' ? { request: async () => 'allowed-once' } : undefined
    },
  }
  apply(ctx, { mode: 'ask' })
  const r = await handlers['tools/pre-execute'](
    { name: 'bash', arguments: { command: 'rm -rf /' } },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(r.kind, 'ask')
})

test('apply：ctx 不支持 get 时也不抛错（安全读服务）', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
  }
  apply(ctx, {})
  const r = await handlers['tools/pre-execute'](
    { name: 'bash', arguments: { command: 'rm -rf /' } },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(r.kind, 'deny')
})

test('拦截器：exec.arguments.command（host 真实结构）被识别', async () => {
  const interceptor = createInterceptor({})
  const r = await interceptor({ name: 'bash', arguments: { command: 'rm -rf /' } })
  assert.equal(r.action, 'block')
  assert.ok(r.reason.includes('fs/rm-root'))
})

test('拦截器：run_code 无命令字段时放行，带 code 时分析', async () => {
  const interceptor = createInterceptor({})
  assert.equal((await interceptor({ name: 'run_code', arguments: { code: 'return 1' } })).action, 'allow')
  assert.equal((await interceptor({ name: 'run_code', arguments: { command: 'rm -rf /' } })).action, 'block')
})
