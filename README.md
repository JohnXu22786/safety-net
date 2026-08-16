[English](README.en.md)

# Barricade（路障）

> 编码 agent 的破坏性命令拦截闸门：在 `rm -rf`、`git reset --hard`、`git push --force` 这类命令真正落地**之前**解析命令语义、判定风险，并要求人工确认。

Barricade 是一枚自包含的插件/CLI，零运行时依赖（纯 Node.js ESM），面向所有「把 shell 交给 agent 去跑」的 harness 设计。它不做沙箱、不限制能力，只做一件事：**把不可逆的操作挡在确认关卡前**——包括那些沙箱也拦不住的（`git reset --hard` 丢弃工作区、`git push --force` 覆盖远端历史、`rm -rf` 删掉工作区内未跟踪文件）。

## 能力一览

- **语义级命令解析**：不是字符串匹配。自带 POSIX 词法分析器，识别引号、转义、heredoc、命令替换 `$(...)`、子 shell、管道链；`bash -c "rm -rf /"`、`sudo rm -rf /`、`eval "rm -rf /"`、`echo $(rm -rf /)` 都逃不过。
- **分命令判定器**：git（reset/clean/push/checkout/branch/stash/restore 等 13 种危险形态，支持长旗标唯一前缀、短旗标解绑）、rm（按目标作用域分级：根目录/主目录/.git → 致命；工作区外/动态目标 → 高危；工作区内 → 中危）、dd/mkfs/shred/chmod/chown、find -delete、curl|sh、解释器单行、fork 炸弹、PowerShell 强删等 41 条内置规则。
- **三级策略**：`relaxed` / `balanced`（默认）/ `vigilant`，严重度 → 动作（拒绝/确认/放行）逐级映射，`vigilant` 下无法解析的输入按需确认（fail-closed）。
- **交互式确认**：TTY 下展示命令与命中规则，支持执行一次 / 拒绝 / 本会话放行 / 永久放行（写入策略）/ 查看详情；非 TTY 环境一律拒绝（失败安全）。
- **多 harness 可移植**：判定核心与 harness 无关（输入 `(命令, 工作目录, 策略)`，输出结构化判定），三种接入形态任选：dsh 进程内插件、通用 stdin-hook JSON 契约、`gate` shell 包装。
- **审计**：拦截与确认记录落盘 JSONL，密钥类内容自动脱敏。

## 工作原理

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

分析引擎的关键环节：

1. **分词**：POSIX 风格词法分析（引号/转义/操作符/heredoc 正文/命令替换提取），输入超限或无法解析时回退到粗粒度模式扫描。
2. **分段**：按 `&&` `||` `;` `|` `&` 与子 shell 切分命令段，`cd` 跟踪执行目录，逐段独立判定，任一危险段拦截整条命令。
3. **拆包装**：递归剥离 `sudo` / `env` / `command` / `timeout` 等包装命令与 `bash -c` / `sh -c` / `su -c` 内嵌负载（深度上限 8，超限按需确认）。
4. **判定合并**：致命优先、任一拒绝则拒绝、任一需确认则确认；策略 overrides 可调整高/中危动作，**致命规则不可降级**。

## 安装

要求 Node.js ≥ 18.13，无任何 npm 依赖。

```bash
# 直接运行（无需安装）
node bin/barricade.js --help

# 作为命令行工具使用（可选）
npm link          # 之后可直接使用 barricade 命令
```

## 接入 dsh（DeepSeek Harness）

本仓库即一个合法的 dsh bundle：`package.json` 声明了 `dsh.bundle`，`cordis.patch.yml` 是配置层补丁，`plugin.js` 是插件入口。

### 在 DSH 中安装

```bash
dsh plugin --profile demo add github:JohnXu22786/safety-net
```

### 加载方式

```bash
# 在目标 profile 中安装本 bundle（本地目录或已发布的 npm 包名）
dsh plugin --profile web add ../dsh-barricade      # 或 dsh plugin --profile web add dsh-barricade

# 启动
dsh --profile web
```

加载后 Cordis 会按 `cordis.patch.yml` 插入插件行：

```yaml
- insert:
    - id: barricade
      name: dsh-barricade
```

### 插件接口

| 项 | 值 |
|---|---|
| 入口 | `plugin.js`（`main` 字段），导出 `name` / `inject` / `apply(ctx, config)` |
| 事件 | 监听工具执行管线事件 `tools/pre-execute`（waterfall），在工具真正执行前介入 |
| 拦截方式 | 判定为需拦截时抛出 `BarricadeBlocked` 错误，工具调用失败且原因对模型可见 |
| 配置 | `cordis.patch.yml` 中 `config` 字段，或 `dsh --patch` 覆盖层 |

可用配置项（均可省略）：

| 配置键 | 默认 | 说明 |
|---|---|---|
| `mode` | `"deny"` | `deny`：命中即拒绝；`ask`：经 `ctx.approval` 服务请求人工确认，确认被拒或服务不可用时按拒绝处理 |
| `toolNames` | 常见 shell 工具名列表 | 仅拦截这些工具；亦可用环境变量 `BARRICADE_TOOLS` 覆盖（逗号分隔） |
| `commandPath` | `"args.command"` | 工具调用中命令文本的取值路径（点路径），兼容 `input.command` / `command` 等形态 |
| `level` | 策略文件 | `relaxed` / `balanced` / `vigilant` |

示例（写入 profile 的 `cordis.patch.yml` 或 `--patch` 覆盖层）：

```yaml
- insert:
    - id: barricade
      name: dsh-barricade
      config:
        mode: ask
        toolNames: [bash, run_code, run_command]
```

> 说明：dsh 当前处于开发者预览期，接口可能演进。`apply` 对工具调用形态做了防御式识别（`name/tool`、`args/input` 等），并对 `ctx.approval` 的多种调用形态做探测；任何形态不可用时按拒绝处理，保证失败安全。若上游事件契约变化，只需调整 `plugin.js` 中的事件名与字段路径。

### 其他 harness 接入

判定核心不依赖任何 harness，以下三种形态任选：

**① stdin-hook 契约**（适用于支持「工具调用前运行钩子」的 harness，如 PreToolUse 类钩子）：

```
stdin  : {"command": "<待执行命令>", "cwd": "<可选>"}    # 或纯命令文本
stdout : {"action": "allow|ask|deny", "severity": ..., "matches": [...], "warnings": [...]}
exit   : 0（正常输出判定）；加 --exit-on-block 时拦截退出 1
```

示例（将钩子命令指向 `node <本目录>/bin/barricade.js hook`）：

```bash
echo '{"command":"git push --force origin main"}' | node bin/barricade.js hook
# {"command":"git push --force origin main","action":"ask","severity":"high",
#  "reason":"强制推送覆盖远端提交历史，可能造成他人工作丢失","matches":[...],"warnings":[]}
```

**② gate 包装**（把 harness 的 shell 换成 `barricade gate -- <命令>`）：终端交互确认后执行，非终端环境直接拦截。

**③ 进程内复用**：`createInterceptor(config)` 返回纯判定函数，任何 Node 进程内 harness 可直接调用（见 `plugin.js` 顶部注释）。

## CLI 使用说明

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

示例：

```bash
barricade check -c "rm -rf /"                 # 退出 1，打印拦截原因
barricade analyze --json -c "git reset --hard"
barricade gate -- "npm run build"             # 终端下交互确认
```

## 策略配置

配置文件：用户级 `~/.barricade/barricade.json`（`BARRICADE_HOME` 可改），项目级 `.barricade.json`（当前目录，优先于用户级）。均为 JSON，字段缺失/损坏时**挽救式回退默认值**并打印警告，绝不让策略文件把工作流打断。

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

| 字段 | 说明 |
|---|---|
| `level` | `relaxed`（中危放行）/ `balanced`（中危确认）/ `vigilant`（+ 无法解析输入按需确认） |
| `failClosed` | 命令无法解析时也要求确认 |
| `allowlist` | 前缀放行清单（`git status` 放行 `git status --porcelain`） |
| `overrides` | 按规则 id 调整动作：`allow` / `ask` / `deny` / `off`；**致命规则不可降级** |
| `rules` | 自定义规则：命令 + 子命令(可选) + 任一参数命中（支持短旗标解绑） |
| `confirmation.timeoutSeconds` | 交互确认超时（秒），超时按拒绝；0 为不超时 |

环境变量（只升不降）：

| 变量 | 说明 |
|---|---|
| `BARRICADE_HOME` | 数据目录（策略、审计日志），默认 `~/.barricade` |
| `BARRICADE_POLICY` | 指定用户策略文件路径 |
| `BARRICADE_LEVEL` | 提升等级（仅当高于文件等级时生效） |
| `BARRICADE_FAIL_CLOSED=1` | 开启 fail-closed |
| `BARRICADE_CONFIRM_TIMEOUT` | 确认超时秒数 |
| `BARRICADE_TOOLS` | dsh 插件拦截的工具名单（逗号分隔） |
| `BARRICADE_NO_COLOR` / `NO_COLOR` | 关闭彩色输出 |

## 交互确认

```
⚠️  Barricade 需要确认此命令 [高危]
命令: git push --force origin main
  • git/push-force — 强制推送覆盖远端提交历史，可能造成他人工作丢失
[y] 执行一次  [n] 拒绝  [s] 本会话放行  [a] 永久放行  [d] 详情  [q] 退出
>
```

- `a` 会把规则写入用户策略文件（`overrides`）；致命规则不可永久放行。
- `s` 把规则记入本次调用的会话集合；`gate` 单次调用内只确认一次，`s` 与 `y` 等价；进程内复用同一 session 集合的场景下可跨调用生效。
- 命令展示前会转义控制字符并截断，防止终端注入（判定文本与审计日志同样处理）。

## 内置规则清单（节选）

| 规则 id | 严重度 | 说明 |
|---|---|---|
| `fs/rm-root` / `fs/rm-home` | 致命 | 删除根目录 / 主目录 |
| `fs/rm-git` | 致命 | 删除/写入/移动 `.git` 内部内容 |
| `fs/mkfs-device` / `fs/dd-device` | 致命/高危 | 格式化或写入块设备（`/dev/null` 等安全目标除外） |
| `fs/rm-outside` / `fs/rm-dynamic` / `fs/rm-workspace` | 高/高/中 | rm -rf 目标作用域分级 |
| `fs/find-delete` / `fs/shred` / `fs/chmod-recursive` / `fs/chown-recursive` | 高/高/中/中 | 批量或递归破坏性操作 |
| `git/reset-hard` / `git/clean-force` / `git/push-force` / `git/push-delete` | 高/高/高/中 | 覆盖历史、丢弃未提交修改、删远端分支 |
| `git/checkout-force` / `git/checkout-discard` / `git/switch-force` / `git/restore-worktree` | 高 | 丢弃工作区修改 |
| `git/branch-delete-force` / `git/stash-drop` / `git/stash-clear` / `git/tag-delete` | 高/高/高/中 | 不可恢复的引用/暂存操作 |
| `git/fetch-force` / `git/ssh-env` | 中/高 | 覆盖远端引用 / GIT_SSH* 与网络子命令组合 |
| `shell/curl-pipe-sh` / `shell/fork-bomb` / `interp/embedded` | 高 | 远程脚本管道、fork 炸弹、解释器内嵌删除代码 |
| `sys/shutdown` / `sys/reboot` / `sys/powershell-remove` / `sys/cmd-del` | 高/高/中/中 | 系统级操作 |

完整清单与动作映射见 `barricade rules`。

## 安全模型与已知边界

- **不是沙箱**，不构成特权边界。它拦截的是「harness 通过受支持入口发起的命令」；绕过集成的方式（例如用编辑器工具直接写文件、在容器外手工执行）不在保护范围内。
- **静态分析的固有局限**：`bash <未知脚本>`、`eval "$X"` 这类运行期才可知的内容无法审查——`vigilant` 等级下会要求确认，默认等级下直接放行（可配置 `failClosed` 或自定义规则收紧）。
- 分析按 POSIX 路径语义处理命令文本，与运行平台无关；Windows 下 `gate` 经 `cmd /c` 执行，命令本身仍按 POSIX 语法分析。
- 输入长度上限 128 KiB、嵌套深度上限 8 层，超限走粗粒度扫描或按需确认，防止构造畸形输入拖垮分析。

## 开发

```bash
node --test        # 或 npm test；测试用例见 test/ 目录
```

结构：

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
