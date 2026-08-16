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

test('拦截器：合法配置的 level 生效', async () => {
  const relaxed = createInterceptor({ level: 'relaxed' })
  // 中危在 relaxed 下放行
  const r = await relaxed({ name: 'bash', args: { command: 'rm -rf ./dist' } })
  assert.equal(r.action, 'allow')
  const vigilant = createInterceptor({ level: 'vigilant' })
  const r2 = await vigilant({ name: 'bash', args: { command: 'rm -rf ./dist' } })
  assert.equal(r2.action, 'block')
})

test('apply：注册 tools/pre-execute 监听并拦截破坏性调用', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
  }
  apply(ctx, {})
  assert.ok(typeof handlers['tools/pre-execute'] === 'function')
  // 安全调用正常返回
  const safe = await handlers['tools/pre-execute']({ name: 'bash', args: { command: 'git status' } })
  assert.equal(safe.name, 'bash')
  // 破坏性调用抛错（即拒绝执行）
  await assert.rejects(
    handlers['tools/pre-execute']({ name: 'bash', args: { command: 'rm -rf /' } }),
    (err) => err.message.includes('fs/rm-root'),
  )
})

test('apply：ask 模式下 approval 放行则不抛错', async () => {
  const handlers = {}
  const ctx = {
    on(event, fn) {
      handlers[event] = fn
    },
    approval: { ask: async () => true },
  }
  apply(ctx, { mode: 'ask' })
  const r = await handlers['tools/pre-execute']({ name: 'bash', args: { command: 'rm -rf /' } })
  assert.equal(r.name, 'bash')
})
