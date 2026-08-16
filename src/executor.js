// 执行器：gate 模式下经系统 shell 真正执行命令（仅放行后调用）。

import os from 'node:os'
import { spawn } from 'node:child_process'

/**
 * 通过系统 shell 执行命令。
 * POSIX: $SHELL -c；Windows: %ComSpec% /d /s /c（verbatim 传参，避免 cmd 引号转义陷阱）
 * @returns {ChildProcess}
 */
export function runThroughShell(command, env = process.env) {
  const isWin = process.platform === 'win32'
  const shell = isWin ? env.ComSpec || 'cmd.exe' : env.SHELL || '/bin/sh'
  if (isWin) {
    return spawn(shell, ['/d', '/s', '/c', command], { stdio: 'inherit', env, windowsVerbatimArguments: true })
  }
  return spawn(shell, ['-c', command], { stdio: 'inherit', env })
}

/** 等待子进程结束，返回退出码（信号终止映射为 128+信号号） */
export function waitExit(child) {
  return new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      if (code !== null) { resolve(code); return }
      if (signal && os.constants.signals[signal] !== undefined) {
        resolve(128 + os.constants.signals[signal])
        return
      }
      resolve(1)
    })
    child.on('error', () => resolve(127))
  })
}
