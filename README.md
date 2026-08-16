[简体中文](README.zh.md)

# Barricade

> A destructive-command interception gate for coding agents: it parses command semantics and judges risk **before** `rm -rf`, `git reset --hard`, `git push --force` and similar commands actually land, then requires human confirmation.

Barricade is a self-contained plugin/CLI with zero runtime dependencies (pure Node.js ESM), designed for any harness that "hands the shell over to an agent". It does not sandbox and does not limit capabilities; it does only one thing: **hold irreversible operations at a confirmation gate** — including those even a sandbox can't stop (`git reset --hard` discards the working tree, `git push --force` overwrites remote history, `rm -rf` deletes untracked files in the workspace).

## Capabilities at a Glance

- **Semantic-level command parsing**: not string matching. Ships its own POSIX lexer that recognizes quotes, escapes, heredocs, command substitution `$(...)`, sub-shells and pipeline chains; `bash -c "rm -rf /"`, `sudo rm -rf /`, `eval "rm -rf /"`, `echo $(rm -rf /)` cannot slip through.
- **Per-command verifiers**: git (reset/clean/push/checkout/branch/stash/restore — 13 dangerous forms, supporting long-flag unique prefixes and short-flag unbinding), rm (tiered by target scope: root/home/.git → fatal; outside workspace / dynamic targets → high; inside workspace → medium), dd/mkfs/shred/chmod/chown, find -delete, curl|sh, interpreter one-liners, fork bombs, PowerShell forced deletion — 41 built-in rules.
- **Three levels**: `relaxed` / `balanced` (default) / `vigilant`, mapping severity → action (deny/ask/allow) tier by tier; under `vigilant`, unparseable inputs ask as needed (fail-closed).
- **Interactive confirmation**: on a TTY it shows the command and matched rules, supporting run once / deny / allow for this session / allow permanently (written to policy) / show details; non-TTY environments always deny (fail-safe).
- **Portable across harnesses**: the verdict core is harness-agnostic (input `(command, cwd, level)`, output structured verdict); three integration forms to choose from: a dsh in-process plugin, a generic stdin-hook JSON contract, and a `gate` shell wrapper.
- **Audit**: interception and confirmation records are persisted as JSONL; secret-like content is automatically redacted.

## How It Works

```
agent 准备执行命令
        │
        ▼
┌─────────────────┐   ┌──────────────┐
│ 接入点(任一)      │──▶│ 命令分析引擎   │
│ dsh 插件事件      │   │ 分词 → 分段   │
│ stdin-hook       │   │ 拆包装 → 判定  │
│ gate 包装        │   └──────┬───────┘
└─────────────────┘          │
                             ▼
                  ┌─ 放行 ──▶ 命令执行
                  │
              判定结果
                  │
                  └─ 需确认 ─▶ TTY 交互确认 ──▶ 执行/拒绝
                              非 TTY：拒绝（失败安全）
```

Key steps of the analysis engine:

1. **Tokenize**: POSIX-style lexing (quotes/escapes/operators/heredoc bodies/command-substitution extraction); falls back to a coarse-grained pattern scan when input is over the limit or unparseable.
2. **Segment**: splits command segments by `&&` `||` `;` `|` `&` and sub-shells; tracks `cd` execution directories; each segment is judged independently, and any dangerous segment blocks the whole command.
3. **Unwrap**: recursively strips wrapper commands like `sudo` / `env` / `command` / `timeout` and embedded loads in `bash -c` / `sh -c` / `su -c` (depth limit 8; beyond the limit, ask as needed).
4. **Verdict merge**: fatal first; any deny → deny; any ask → ask; policy `overrides` can adjust high/medium actions, but **fatal rules cannot be downgraded**.

## Installation

Requires Node.js ≥ 18.13, no npm dependencies.

```bash
# 直接运行（无需安装）
node bin/barricade.js --help

# 作为命令行工具使用（可选）
npm link          # 之后可直接使用 barricade 命令
```

## Integrating with dsh (DeepSeek Harness)

This repository is a valid dsh bundle: `package.json` declares `dsh.bundle`, `cordis.patch.yml` is the config-layer patch, and `plugin.js` is the plugin entry point.

### Installing in DSH

```bash
dsh plugin --profile demo add github:JohnXu22786/safety-net
```

### Loading

```bash
# 在目标 profile 中安装本 bundle（本地目录或已发布的 npm 包名）
dsh plugin --profile web add ../dsh-barricade      # 或 dsh plugin --profile web add dsh-barricade

# 启动
dsh --profile web
```

After loading, Cordis inserts the plugin line per `cordis.patch.yml`:

```yaml
- insert:
    - id: barricade
      name: dsh-barricade
```

### Plugin Interface

| Item | Value |
|---|---|
| Entry | `plugin.js` (`main` field), exports `name` / `inject` / `apply(ctx, config)` |
| Events | listens to the tool execution pipeline event `tools/pre-execute` (waterfall), intervening before the tool actually runs |
| Interception | throws `BarricadeBlocked` when a block verdict is produced; the tool call fails and the reason is visible to the model |
| Config | the `config` field in `cordis.patch.yml`, or a `dsh --patch` overlay |

Available config keys (all optional):

| Key | Default | Description |
|---|---|---|
| `mode` | `"deny"` | `deny`: deny on match; `ask`: request human confirmation through the `ctx.approval` service; if confirmation is refused or the service is unavailable, treat as deny |
| `toolNames` | common shell tool name list | only intercept these tools; can also be overridden via the `BARRICADE_TOOLS` env var (comma-separated) |
| `commandPath` | `"args.command"` | dot-path to the command text in the tool call; compatible with `input.command` / `command` and other shapes |
| `level` | policy file | `relaxed` / `balanced` / `vigilant` |

Example (written into the profile's `cordis.patch.yml` or a `--patch` overlay):

```yaml
- insert:
    - id: barricade
      name: dsh-barricade
      config:
        mode: ask
        toolNames: [bash, run_code, run_command]
```

> Note: dsh is currently in developer preview and its interfaces may evolve. `apply` defensively recognizes tool-call shapes (`name/tool`, `args/input`, etc.) and probes the various calling forms of `ctx.approval`; if any form is unavailable it falls back to deny, keeping fail-safe. If the upstream event contract changes, just adjust the event name and field paths in `plugin.js`.

### Other Harness Integration

The verdict core depends on no harness; pick any of the three forms:

**① stdin-hook contract** (for harnesses that support "run a hook before tool invocation", such as PreToolUse-style hooks):

```
stdin  : {"command": "<待执行命令>", "cwd": "<可选>"}    # 或纯命令文本
stdout : {"action": "allow|ask|deny", "severity": ..., "matches": [...], "warnings": [...]}
exit   : 0（正常输出判定）；加 --exit-on-block 时拦截退出 1
```

Example (point the hook command at `node <本目录>/bin/barricade.js hook`):

```bash
echo '{"command":"git push --force origin main"}' | node bin/barricade.js hook
# {"command":"git push --force origin main","action":"ask","severity":"high",
#  "reason":"强制推送覆盖远端提交历史，可能造成他人工作丢失","matches":[...],"warnings":[]}
```

**② gate wrapper** (swap the harness's shell for `barricade gate -- <command>`): executes after terminal confirmation; non-terminal environments are blocked outright.

**③ in-process reuse**: `createInterceptor(config)` returns a pure verdict function callable from any Node in-process harness (see the comments at the top of `plugin.js`).

## CLI Usage

```
barricade <子命令> [选项]

  analyze [--json] <命令>              分析并输出判定（不执行；退出码恒 0）
  check   [--json] [--quiet] <命令>    判定；放行退出 0，拦截退出 1
  gate -- <命令>                       分析 + 交互确认 + 执行
  hook                                 见上文 stdin-hook 契约
  policy --show [--json]               显示合并后的策略
  policy --validate [--policy F]       校验策略文件
  rules [--json]                       列出内置规则
  audit [--tail N]                     查看审计记录

  -c, --command <命令>    --stdin       命令输入方式
  --level <等级>          --policy <F>  临时等级 / 指定策略文件
  --json                  --quiet       --exit-on-block
  -h, --help              -v, --version --tail <N>
```

Examples:

```bash
barricade check -c "rm -rf /"                 # 退出 1，打印拦截原因
barricade analyze --json -c "git reset --hard"
barricade gate -- "npm run build"             # 终端下交互确认
```

## Policy Configuration

Config files: user-level `~/.barricade/barricade.json` (`BARRICADE_HOME` to change), project-level `.barricade.json` (current directory, takes precedence over user-level). Both are JSON; missing/corrupt fields **rescue-fall back to defaults** with a warning — a policy file can never interrupt your workflow.

```json
{
  "version": 1,
  "level": "balanced",
  "failClosed": false,
  "allowlist": ["git status", "git log", "ls -la"],
  "overrides": { "git/tag-delete": "allow" },
  "rules": [
    {
      "id": "custom/dropdb-force",
      "command": "dropdb",
      "args": ["--force"],
      "severity": "high",
      "reason": "强制删除数据库不可恢复"
    }
  ],
  "confirmation": { "sessionMemory": true, "timeoutSeconds": 0 }
}
```

| Field | Description |
|---|---|
| `level` | `relaxed` (medium allowed) / `balanced` (medium asks) / `vigilant` (+ unparseable input asks as needed) |
| `failClosed` | require confirmation even when a command cannot be parsed |
| `allowlist` | prefix allowlist (`git status` allows `git status --porcelain`) |
| `overrides` | adjust per-rule-id actions: `allow` / `ask` / `deny` / `off`; **fatal rules cannot be downgraded** |
| `rules` | custom rules: command + optional subcommand + any arg match (short-flag unbinding supported) |
| `confirmation.timeoutSeconds` | interactive confirmation timeout (seconds); timeout counts as deny; 0 means no timeout |

Environment variables (raise-only, never lower):

| Variable | Description |
|---|---|
| `BARRICADE_HOME` | data directory (policy, audit logs), default `~/.barricade` |
| `BARRICADE_POLICY` | specify a user policy file path |
| `BARRICADE_LEVEL` | raise the level (only takes effect when higher than the file level) |
| `BARRICADE_FAIL_CLOSED=1` | enable fail-closed |
| `BARRICADE_CONFIRM_TIMEOUT` | confirmation timeout seconds |
| `BARRICADE_TOOLS` | comma-separated list of tools the dsh plugin intercepts |
| `BARRICADE_NO_COLOR` / `NO_COLOR` | disable colored output |

## Interactive Confirmation

```
⚠️  Barricade 需要确认此命令 [高危]
命令: git push --force origin main
  • git/push-force — 强制推送覆盖远端提交历史，可能造成他人工作丢失
[y] 执行一次  [n] 拒绝  [s] 本会话放行  [a] 永久放行  [d] 详情  [q] 退出
>
```

- `a` writes the rule into the user policy file (`overrides`); fatal rules cannot be allowed permanently.
- `s` records the rule into this invocation's session set; within a single `gate` call it confirms only once, so `s` is equivalent to `y`; it can take effect across calls when the same session set is reused in-process.
- Control characters are escaped and the command truncated before display, preventing terminal injection (the verdict text and audit logs are handled the same way).

## Built-in Rules (excerpt)

| Rule id | Severity | Description |
|---|---|---|
| `fs/rm-root` / `fs/rm-home` | fatal | delete root / home directory |
| `fs/rm-git` | fatal | delete/write/move `.git` internals |
| `fs/mkfs-device` / `fs/dd-device` | fatal/high | format or write block devices (safe targets such as `/dev/null` excluded) |
| `fs/rm-outside` / `fs/rm-dynamic` / `fs/rm-workspace` | high/high/medium | rm -rf target scope tiers |
| `fs/find-delete` / `fs/shred` / `fs/chmod-recursive` / `fs/chown-recursive` | high/high/medium/medium | bulk or recursive destructive operations |
| `git/reset-hard` / `git/clean-force` / `git/push-force` / `git/push-delete` | high/high/high/medium | overwrite history, discard uncommitted changes, delete remote branches |
| `git/checkout-force` / `git/checkout-discard` / `git/switch-force` / `git/restore-worktree` | high | discard working-tree changes |
| `git/branch-delete-force` / `git/stash-drop` / `git/stash-clear` / `git/tag-delete` | high/high/high/medium | unrecoverable ref/stash operations |
| `git/fetch-force` / `git/ssh-env` | medium/high | overwrite remote refs / GIT_SSH* combined with network subcommands |
| `shell/curl-pipe-sh` / `shell/fork-bomb` / `interp/embedded` | high | remote-script piping, fork bombs, interpreter-embedded deletion code |
| `sys/shutdown` / `sys/reboot` / `sys/powershell-remove` / `sys/cmd-del` | high/high/medium/medium | system-level operations |

The full list and action mapping: `barricade rules`.

## Security Model and Known Boundaries

- **Not a sandbox**, and not a privilege boundary. It intercepts "commands the harness issues through supported entry points"; bypassing the integration (e.g. writing files directly with an editor tool, executing manually outside a container) is out of protection scope.
- **Inherent limits of static analysis**: runtime-only content such as `bash <unknown script>` and `eval "$X"` cannot be inspected — under `vigilant` they require confirmation; under the default level they pass (tightenable with `failClosed` or custom rules).
- Analysis handles command text with POSIX path semantics, independent of the running platform; on Windows, `gate` runs via `cmd /c`, while the command itself is still parsed with POSIX syntax.
- Input size limit 128 KiB and nesting depth limit 8; beyond the limits it falls back to coarse-grained scanning or asks as needed, preventing malformed input from stalling analysis.

## Development

```bash
node --test        # 或 npm test；测试用例见 test/ 目录
```

Structure:

```
bin/barricade.js    CLI 入口
plugin.js           dsh（Cordis）插件入口
src/
  tokenizer.js      词法分析（引号/heredoc/命令替换）
  analyzer.js       命令段组织、包装拆解、分命令判定
  rules.js          内置规则库与等级映射
  verdict.js        判定合并模型
  policy.js         策略加载与挽救式校验
  prompt.js         交互确认
  audit.js          审计日志（脱敏）
  executor.js       gate 执行器
cordis.patch.yml    dsh 配置层补丁
examples/           示例配置与 hook 契约样例
test/               181 个测试用例
```

## License

[MIT](LICENSE)