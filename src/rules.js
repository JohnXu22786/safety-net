// 内置规则库：规则元数据 + 等级映射。
// 每条规则带中文说明（reason），命中时组合进判定结果展示给用户。

export const LEVELS = ['relaxed', 'balanced', 'vigilant']

/** 等级顺序，用于“环境变量只能提升等级”等逻辑 */
export const LEVEL_ORDER = { relaxed: 0, balanced: 1, vigilant: 2 }

/** 严重度排序 */
export const SEVERITY_RANK = { critical: 3, high: 2, medium: 1 }

export const SEVERITY_LABEL = { critical: '致命', high: '高危', medium: '中危' }

/**
 * 各等级下严重度 → 默认动作：
 *   deny 直接拒绝；ask 需要人工确认；allow 放行
 */
export const ACTION_BY_LEVEL = {
  relaxed: { critical: 'deny', high: 'ask', medium: 'allow' },
  balanced: { critical: 'deny', high: 'ask', medium: 'ask' },
  vigilant: { critical: 'deny', high: 'ask', medium: 'ask' },
}

/**
 * 内置规则。severity 为默认严重度，个别规则在命中时会按目标动态调整
 * （如 chmod -R 目标为根目录时提升为 critical）。
 */
export const BUILTIN_RULES = [
  { id: 'fs/rm-root', severity: 'critical', title: '递归删除根目录', reason: '将删除文件系统根目录下的全部内容，系统无法启动' },
  { id: 'fs/rm-home', severity: 'critical', title: '递归删除主目录', reason: '将删除整个用户主目录，个人数据全部丢失' },
  { id: 'fs/rm-git', severity: 'critical', title: '破坏 git 元数据', reason: '目标位于 .git 内部，删除或写入会破坏仓库历史与状态' },
  { id: 'fs/rm-outside', severity: 'high', title: '删除工作区外路径', reason: '目标位于当前工作区之外，可能波及未纳入版本控制的重要数据' },
  { id: 'fs/rm-dynamic', severity: 'high', title: '动态目标递归删除', reason: '删除目标由变量或命令替换决定，静态分析无法确认其范围' },
  { id: 'fs/rm-workspace', severity: 'medium', title: '递归删除工作区内内容', reason: '递归删除将不可恢复地移除工作区内文件（已跟踪文件可由 git 恢复，未跟踪文件不能）' },
  { id: 'fs/chmod-recursive', severity: 'medium', title: '递归修改权限', reason: '递归权限修改影响整棵目录树，误操作会导致系统或应用不可用' },
  { id: 'fs/chown-recursive', severity: 'medium', title: '递归修改属主', reason: '递归属主修改影响整棵目录树，误操作会导致权限错乱' },
  { id: 'fs/shred', severity: 'high', title: '擦除文件', reason: 'shred 覆盖文件内容，删除后不可恢复' },
  { id: 'fs/dd-device', severity: 'high', title: '写入块设备', reason: '直接向磁盘设备写入将覆盖分区或磁盘数据' },
  { id: 'fs/mkfs-device', severity: 'critical', title: '格式化设备', reason: '格式化将清空设备上的全部数据' },
  { id: 'fs/mkfs-image', severity: 'medium', title: '格式化镜像文件', reason: '格式化将清空目标文件内容' },
  { id: 'fs/find-delete', severity: 'high', title: 'find -delete 批量删除', reason: '按条件批量删除文件，实际影响范围可能大于预期' },
  { id: 'git/reset-hard', severity: 'high', title: 'git reset --hard', reason: '将工作区与暂存区重置为目标提交，未提交修改永久丢失' },
  { id: 'git/clean-force', severity: 'high', title: 'git clean -f', reason: '强制删除所有未跟踪文件与目录' },
  { id: 'git/push-force', severity: 'high', title: '强制推送', reason: '强制推送覆盖远端提交历史，可能造成他人工作丢失' },
  { id: 'git/push-delete', severity: 'medium', title: '删除远端分支', reason: '删除远端分支，影响团队协作' },
  { id: 'git/checkout-force', severity: 'high', title: '强制检出', reason: '强制检出将丢弃工作区未提交修改' },
  { id: 'git/checkout-discard', severity: 'high', title: 'git checkout -- 丢弃修改', reason: '将工作区文件重置为暂存区内容，本地修改丢失' },
  { id: 'git/switch-force', severity: 'high', title: '强制切换分支', reason: '强制切换将丢弃工作区未提交修改' },
  { id: 'git/branch-delete-force', severity: 'high', title: '强制删除分支', reason: '强制删除分支将丢弃该分支上的全部提交' },
  { id: 'git/branch-force-move', severity: 'high', title: '强制移动分支', reason: '强制移动分支将丢弃该分支上原有提交' },
  { id: 'git/tag-delete', severity: 'medium', title: '删除标签', reason: '删除标签，历史引用丢失' },
  { id: 'git/stash-drop', severity: 'high', title: '丢弃 stash', reason: '丢弃指定 stash，其中内容不可恢复' },
  { id: 'git/stash-clear', severity: 'high', title: '清空全部 stash', reason: '清空全部 stash，内容不可恢复' },
  { id: 'git/restore-worktree', severity: 'high', title: '还原工作区文件', reason: '将工作区文件还原为索引或提交内容，本地修改丢失' },
  { id: 'git/fetch-force', severity: 'medium', title: '强制更新远端引用', reason: '强制更新远端引用，可能覆盖本地分支引用' },
  { id: 'git/ssh-env', severity: 'high', title: 'git 网络操作携带 GIT_SSH* 覆盖', reason: 'GIT_SSH_COMMAND 等变量使 git 在联网操作时执行任意程序' },
  { id: 'shell/curl-pipe-sh', severity: 'high', title: '远程脚本管道到 shell', reason: '将远程内容直接交给 shell 执行，内容不可预知' },
  { id: 'shell/fork-bomb', severity: 'high', title: 'fork 炸弹', reason: '该命令会无限复制进程直至系统资源耗尽' },
  { id: 'shell/eval-dynamic', severity: 'medium', title: 'eval 动态内容', reason: 'eval 将执行运行时构造的代码，无法静态确认内容' },
  { id: 'shell/source-unknown', severity: 'medium', title: '执行未知脚本', reason: 'source 将执行目标文件内容，当前无法审查' },
  { id: 'shell/depth-limit', severity: 'high', title: '嵌套深度超限', reason: '包装嵌套过深，无法完整分析，安全起见需人工确认' },
  { id: 'shell/unparseable', severity: 'medium', title: '无法解析的命令', reason: '命令语法无法解析，failClosed 模式下要求人工确认' },
  { id: 'shell/ifs-obfuscation', severity: 'medium', title: '$IFS 拼接混淆', reason: '命令含 $IFS 拼接，词法结构不可信，需人工确认' },
  { id: 'interp/embedded', severity: 'high', title: '解释器内嵌破坏性代码', reason: '单行脚本内包含删除类系统调用' },
  { id: 'sys/shutdown', severity: 'high', title: '关机/断电', reason: '将关闭或切断系统电源' },
  { id: 'sys/reboot', severity: 'high', title: '重启系统', reason: '将重启系统' },
  { id: 'sys/powershell-remove', severity: 'medium', title: 'PowerShell 强制删除', reason: 'Remove-Item -Recurse -Force 将不可恢复地删除目标' },
  { id: 'sys/powershell-opaque', severity: 'medium', title: 'PowerShell 编码命令', reason: '编码命令内容无法静态审查' },
  { id: 'sys/cmd-del', severity: 'medium', title: 'cmd 递归静默删除', reason: 'del /s /q 批量静默删除文件' },
]

const RULE_INDEX = new Map(BUILTIN_RULES.map((r) => [r.id, r]))

/** 按 id 查找内置规则 */
export function findRule(id) {
  return RULE_INDEX.get(id) ?? null
}

/** 构造命中条目 */
export function mkMatch(rule, message, severity = rule.severity) {
  return { ruleId: rule.id, title: rule.title, severity, message }
}
