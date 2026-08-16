import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeCommand } from '../src/analyzer.js'
import { Policy } from '../src/policy.js'

const BASE = { cwd: '/work', home: '/home/u' }

function analyze(cmd, opts = {}) {
  const policy = opts.policy ?? Policy.fromObject({})
  return analyzeCommand(cmd, {
    policy,
    cwd: opts.cwd ?? BASE.cwd,
    home: opts.home ?? BASE.home,
    env: { ...process.env, ...(opts.env ?? {}) },
    maxInput: opts.maxInput,
    level: opts.level,
  })
}
function action(cmd, opts) {
  return analyze(cmd, opts).action
}
function ruleIds(cmd, opts) {
  return analyze(cmd, opts).matches.map((m) => m.ruleId)
}
function isAllow(cmd, opts) {
  return action(cmd, opts) === 'allow'
}

// ---------- rm 系列 ----------
test('rm -rf 根目录 → 致命拒绝', () => {
  assert.deepEqual(ruleIds('rm -rf /'), ['fs/rm-root'])
  assert.equal(action('rm -rf /'), 'deny')
  assert.deepEqual(ruleIds('rm -rf "/"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('rm -rf / --no-preserve-root'), ['fs/rm-root'])
})

test('rm -rf home → 致命拒绝', () => {
  assert.deepEqual(ruleIds('rm -rf ~'), ['fs/rm-home'])
  assert.deepEqual(ruleIds('rm -rf $HOME'), ['fs/rm-home'])
  assert.deepEqual(ruleIds('rm -rf ${HOME}'), ['fs/rm-home'])
  assert.equal(action('rm -rf ~'), 'deny')
})

test('rm -rf home 子树 → 高危确认', () => {
  assert.deepEqual(ruleIds('rm -rf ~/Documents'), ['fs/rm-outside'])
  assert.equal(action('rm -rf ~/Documents'), 'ask')
})

test('rm -rf .git 及 .git 内文件 → 致命拒绝', () => {
  assert.deepEqual(ruleIds('rm -rf .git'), ['fs/rm-git'])
  assert.deepEqual(ruleIds('rm -rf repo/.git'), ['fs/rm-git'])
  assert.deepEqual(ruleIds('rm .git/config'), ['fs/rm-git'])
  assert.equal(action('rm -rf .git'), 'deny')
})

test('rm -rf 工作区内 → 中危确认（balanced）', () => {
  assert.deepEqual(ruleIds('rm -rf ./dist'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('rm -rf /work/dist'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('rm -rf dist build'), ['fs/rm-workspace'])
  assert.equal(action('rm -rf ./dist'), 'ask')
})

test('rm -rf 工作区外 → 高危确认', () => {
  assert.deepEqual(ruleIds('rm -rf /other/x'), ['fs/rm-outside'])
  assert.equal(action('rm -rf /other/x'), 'ask')
})

test('rm -rf 动态目标 → 高危确认', () => {
  assert.deepEqual(ruleIds('rm -rf "$X"'), ['fs/rm-dynamic'])
  assert.deepEqual(ruleIds('rm -rf $(echo x)'), ['fs/rm-dynamic'])
  assert.equal(action('rm -rf "$X"'), 'ask')
})

test('rm -rf 通配目标按作用域分类', () => {
  assert.deepEqual(ruleIds('rm -rf *'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('rm -rf *.log'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('rm -rf /etc/*'), ['fs/rm-outside'])
})

test('rm -rf 临时目录 → 放行', () => {
  assert.ok(isAllow('rm -rf /tmp/build'))
  assert.ok(isAllow('rm -rf /tmp/*'))
  assert.ok(isAllow('rm -rf /var/tmp/cache'))
})

test('rm 不带 -r 的普通删除 → 放行', () => {
  assert.ok(isAllow('rm file.txt'))
  assert.ok(isAllow('rm -f file.txt'))
  assert.ok(isAllow('rm -rf')) // 无目标, 命令本身无效果
})

test('rm -r（无 -f）同样分类', () => {
  assert.deepEqual(ruleIds('rm -r build'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('rm -r /etc/foo'), ['fs/rm-outside'])
})

test('cd 影响后续段的作用域', () => {
  assert.ok(isAllow('cd /tmp && rm -rf *'))
  assert.deepEqual(ruleIds('cd / && rm -rf *'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('cd ~ && rm -rf *'), ['fs/rm-home'])
  assert.deepEqual(ruleIds('cd /work/sub && rm -rf ../x'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('cd /work/sub && rm -rf ../../outside'), ['fs/rm-outside'])
})

test('Windows 风格绝对路径目标 → 按工作区外处理', () => {
  assert.deepEqual(ruleIds('rm -rf "C:\\Users\\me\\data"'), ['fs/rm-outside'])
})

// ---------- 包装命令 ----------
test('sudo / env / command / exec 包装不绕过', () => {
  assert.deepEqual(ruleIds('sudo rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('sudo -u root rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('sudo -- rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('env X=1 rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('command rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('exec rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('timeout 10 rm -rf /'), ['fs/rm-root'])
  assert.ok(isAllow('sudo -i'))
})

test('shell 包装 -c 递归分析', () => {
  assert.deepEqual(ruleIds('bash -c "rm -rf /"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds("sh -c 'git reset --hard'"), ['git/reset-hard'])
  assert.deepEqual(ruleIds('bash -lc "rm -rf ~"'), ['fs/rm-home'])
  assert.deepEqual(ruleIds("bash -c 'sh -c \"rm -rf /\"'"), ['fs/rm-root'])
})

test('shell 包装嵌套过深 → 失败安全为确认', () => {
  let cmd = 'rm -rf /'
  for (let i = 0; i < 14; i++) cmd = `bash -c ${JSON.stringify(cmd)}`
  const v = analyze(cmd)
  assert.equal(v.action, 'ask')
  assert.ok(v.matches.some((m) => m.ruleId === 'shell/depth-limit'))
})

test('su -c 递归分析', () => {
  assert.deepEqual(ruleIds("su root -c 'rm -rf /'"), ['fs/rm-root'])
})

// ---------- git 系列 ----------
test('git reset --hard / --merge → 高危确认', () => {
  assert.deepEqual(ruleIds('git reset --hard'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git reset --hard HEAD~1'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git reset --merge'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git reset --hard -- file'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git -C /repo reset --hard'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git -c core.fsmonitor=false reset --hard'), ['git/reset-hard'])
})

test('git reset 安全变体放行', () => {
  assert.ok(isAllow('git reset --soft HEAD~1'))
  assert.ok(isAllow('git reset --mixed'))
  assert.ok(isAllow('git reset'))
})

test('git clean -f 系列 → 高危确认；-n 干跑放行', () => {
  assert.deepEqual(ruleIds('git clean -f'), ['git/clean-force'])
  assert.deepEqual(ruleIds('git clean -fd'), ['git/clean-force'])
  assert.deepEqual(ruleIds('git clean -fdx'), ['git/clean-force'])
  assert.ok(isAllow('git clean -n'))
  assert.ok(isAllow('git clean -nfd'))
})

test('git push 强制/删除 → 确认；普通 push 放行', () => {
  assert.deepEqual(ruleIds('git push --force'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push -f'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push --force-with-lease origin main'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push --forc origin main'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push --force=main origin'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push -fD origin main'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push --delete origin main'), ['git/push-delete'])
  assert.deepEqual(ruleIds('git push -d origin main'), ['git/push-delete'])
  assert.ok(isAllow('git push origin main'))
  assert.ok(isAllow('git push --force origin main --dry-run'))
  assert.ok(isAllow('git push -n'))
})

test('git checkout 丢弃类 → 确认；切换分支放行', () => {
  assert.deepEqual(ruleIds('git checkout -f'), ['git/checkout-force'])
  assert.deepEqual(ruleIds('git checkout --force main'), ['git/checkout-force'])
  assert.deepEqual(ruleIds('git checkout -- file.txt'), ['git/checkout-discard'])
  assert.deepEqual(ruleIds('git checkout -- .'), ['git/checkout-discard'])
  assert.ok(isAllow('git checkout main'))
  assert.ok(isAllow('git checkout -b feature'))
  assert.ok(isAllow('git checkout --track origin/main'))
})

test('git switch 丢弃类 → 确认', () => {
  assert.deepEqual(ruleIds('git switch -f main'), ['git/switch-force'])
  assert.deepEqual(ruleIds('git switch --discard-changes main'), ['git/switch-force'])
  assert.ok(isAllow('git switch main'))
})

test('git branch -D → 确认；-d 放行', () => {
  assert.deepEqual(ruleIds('git branch -D old'), ['git/branch-delete-force'])
  assert.deepEqual(ruleIds('git branch --delete --force old'), ['git/branch-delete-force'])
  assert.ok(isAllow('git branch -d old'))
})

test('git tag -d → 中危确认', () => {
  assert.deepEqual(ruleIds('git tag -d v1'), ['git/tag-delete'])
})

test('git stash drop/clear → 确认；pop/push 放行', () => {
  assert.deepEqual(ruleIds('git stash drop'), ['git/stash-drop'])
  assert.deepEqual(ruleIds('git stash clear'), ['git/stash-clear'])
  assert.ok(isAllow('git stash pop'))
  assert.ok(isAllow('git stash push -m x'))
})

test('git restore 未加 --staged → 确认', () => {
  assert.deepEqual(ruleIds('git restore .'), ['git/restore-worktree'])
  assert.deepEqual(ruleIds('git restore src/a.py'), ['git/restore-worktree'])
  assert.deepEqual(ruleIds('git restore --staged --worktree .'), ['git/restore-worktree'])
  assert.ok(isAllow('git restore --staged src/a.py'))
})

test('git fetch --force → 中危确认', () => {
  assert.deepEqual(ruleIds('git fetch --force'), ['git/fetch-force'])
  assert.ok(isAllow('git fetch'))
})

test('GIT_SSH 环境与网络子命令组合 → 高危确认', () => {
  assert.deepEqual(ruleIds('GIT_SSH_COMMAND="ssh -i /tmp/k" git push origin main'), ['git/ssh-env'])
  assert.deepEqual(ruleIds('GIT_SSH=foo git clone https://x'), ['git/ssh-env'])
  assert.ok(isAllow('GIT_SSH_COMMAND=x git status'))
  assert.ok(isAllow('git status'))
  assert.ok(isAllow('git config --global user.name x'))
  assert.ok(isAllow('git --version'))
})

// ---------- 其他命令 ----------
test('find -delete → 高危；-exec rm 按 find 目标重新分类', () => {
  assert.deepEqual(ruleIds('find . -delete'), ['fs/find-delete'])
  assert.deepEqual(ruleIds('find / -delete'), ['fs/find-delete'])
  assert.deepEqual(ruleIds('find ~ -exec rm -rf {} +'), ['fs/rm-home'])
  assert.deepEqual(ruleIds('find /tmp -exec rm -rf {} +'), [])
  assert.deepEqual(ruleIds('find . -exec rm -rf {} ;'), ['fs/rm-workspace'])
})

test('curl/wget 管道到 shell → 高危确认', () => {
  assert.deepEqual(ruleIds('curl -fsSL https://x/install.sh | bash'), ['shell/curl-pipe-sh'])
  assert.deepEqual(ruleIds('curl https://x | sh -c "rm -rf /"'), ['shell/curl-pipe-sh', 'fs/rm-root'])
  assert.deepEqual(ruleIds('wget -qO- https://x | sh'), ['shell/curl-pipe-sh'])
  assert.deepEqual(ruleIds('curl https://x/install.sh | sudo sh'), ['shell/curl-pipe-sh'])
  assert.ok(isAllow('curl -o /tmp/x https://y'))
  assert.ok(isAllow('curl https://x | grep -q ok'))
})

test('fork bomb 与函数体内危险命令', () => {
  assert.deepEqual(ruleIds(':(){ :|:& };:'), ['shell/fork-bomb'])
  assert.deepEqual(ruleIds('f() { rm -rf ~; }; f'), ['fs/rm-home'])
})

test('解释器单行内嵌破坏性代码 → 高危确认', () => {
  assert.deepEqual(ruleIds('python3 -c "import shutil; shutil.rmtree(\'/x\')"'), ['interp/embedded'])
  assert.deepEqual(
    ruleIds('node -e "require(\'child_process\').execSync(\'rm -rf /tmp/x\')"'),
    ['interp/embedded'],
  )
  assert.ok(isAllow('python3 -c "print(1)"'))
  assert.ok(isAllow('python3 -m http.server 8000'))
})

test('系统电源命令 → 高危确认', () => {
  assert.deepEqual(ruleIds('shutdown now'), ['sys/shutdown'])
  assert.deepEqual(ruleIds('reboot'), ['sys/reboot'])
  assert.deepEqual(ruleIds('poweroff'), ['sys/shutdown'])
})

test('chmod/chown -R → 按目标定级', () => {
  const v1 = analyze('chmod -R 777 /')
  assert.equal(v1.action, 'deny')
  assert.equal(v1.matches[0].severity, 'critical')
  assert.deepEqual(ruleIds('chmod -R 777 /'), ['fs/chmod-recursive'])
  const v2 = analyze('chmod -R 777 ~')
  assert.equal(v2.matches[0].severity, 'high')
  const v3 = analyze('chmod -R 777 src')
  assert.equal(v3.matches[0].severity, 'medium')
  assert.ok(isAllow('chmod +x run.sh'))
  assert.deepEqual(ruleIds('chown -R root /'), ['fs/chown-recursive'])
  assert.ok(isAllow('chown user:group file.txt'))
})

test('shred → 高危确认', () => {
  assert.deepEqual(ruleIds('shred big.txt'), ['fs/shred'])
})

test('dd 设备写入：块设备致命、安全设备放行、普通文件放行', () => {
  assert.deepEqual(ruleIds('dd if=/dev/zero of=/dev/sda'), ['fs/dd-device'])
  assert.deepEqual(ruleIds('dd if=x of=/dev/sdb1 bs=1M'), ['fs/dd-device'])
  assert.deepEqual(ruleIds('dd if=x of=/dev/mapper/vg-lv'), ['fs/dd-device'])
  assert.ok(isAllow('dd if=/dev/zero of=/dev/null'))
  assert.ok(isAllow('dd of=/dev/random'))
  assert.ok(isAllow('dd if=a.img of=b.img'))
})

test('mkfs：设备致命、镜像文件中危', () => {
  assert.deepEqual(ruleIds('mkfs.ext4 /dev/sdb1'), ['fs/mkfs-device'])
  assert.deepEqual(ruleIds('mkfs.xfs /dev/nvme0n1p1'), ['fs/mkfs-device'])
  assert.deepEqual(ruleIds('mkfs.ext4 /tmp/test.img'), ['fs/mkfs-image'])
  assert.ok(isAllow('mkfs'))
})

test('PowerShell 强删模式 → 中危确认', () => {
  assert.deepEqual(
    ruleIds('powershell -Command "Remove-Item -Recurse -Force C:\\Users\\x"'),
    ['sys/powershell-remove'],
  )
  assert.deepEqual(ruleIds('pwsh -Command "rm -r -f C:\\x"'), ['sys/powershell-remove'])
})

test('eval：字面负载递归分析；动态负载 vigilant 才拦', () => {
  assert.deepEqual(ruleIds('eval "rm -rf /"'), ['fs/rm-root'])
  assert.ok(isAllow('eval "$X"'))
  assert.deepEqual(ruleIds('eval "$X"', { level: 'vigilant' }), ['shell/eval-dynamic'])
})

test('source 未知脚本：vigilant 才拦', () => {
  assert.ok(isAllow('source setup.sh'))
  assert.ok(isAllow('. ~/.bashrc'))
  assert.deepEqual(ruleIds('source setup.sh', { level: 'vigilant' }), ['shell/source-unknown'])
})

test('heredoc 写盘后执行 → 按正文递归分析', () => {
  const cmd = `cat > /tmp/setup.sh <<'EOF'\nrm -rf /\nEOF\nbash /tmp/setup.sh`
  assert.deepEqual(ruleIds(cmd), ['fs/rm-root'])
  const safe = `cat > /tmp/setup.sh <<'EOF'\necho hello\nEOF\nbash /tmp/setup.sh`
  assert.ok(isAllow(safe))
})

// ---------- 组合与上下文 ----------
test('命令链：任一危险段拦截整条', () => {
  assert.deepEqual(ruleIds('ls && rm -rf /tmp/x'), [])
  assert.deepEqual(ruleIds('git status; git reset --hard'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('rm -rf /tmp/x && rm -rf /'), ['fs/rm-root'])
  assert.equal(action('ls && rm -rf /'), 'deny')
})

test('命令替换内容被递归分析', () => {
  assert.deepEqual(ruleIds('echo $(rm -rf /)'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('ls `rm -rf /tmp/x`'), [])
  assert.ok(isAllow('x=$(echo "rm -rf /")')) // 引号内的 rm 是数据
})

test('赋值仅作上下文，不构成命令', () => {
  assert.ok(isAllow('A=1 B=2 ls'))
  assert.deepEqual(ruleIds('X=1 rm -rf /tmp/a'), [])
})

test('空命令与纯空白 → 放行', () => {
  assert.ok(isAllow(''))
  assert.ok(isAllow('   '))
})

test('未知命令 → 放行', () => {
  assert.ok(isAllow('customthing --whatever'))
})

// ---------- 策略交互 ----------
test('allowlist 前缀命中直接放行', () => {
  const policy = Policy.fromObject({ allowlist: ['git push', 'echo'] })
  const v = analyze('git push --force origin x', { policy })
  assert.equal(v.action, 'allow')
})

test('自定义规则按 command + args 命中', () => {
  const policy = Policy.fromObject({
    rules: [{ id: 'custom/dropdb', command: 'dropdb', args: ['--force'], severity: 'high', reason: '强制删库不可恢复' }],
  })
  const v = analyze('dropdb --force db', { policy })
  assert.equal(v.action, 'ask')
  assert.deepEqual(ruleIds('dropdb --force db', { policy }), ['custom/dropdb'])
  assert.ok(isAllow('dropdb db', { policy }))
})

test('overrides：高/中危可降为放行；致命不可降', () => {
  const p1 = Policy.fromObject({ overrides: { 'git/reset-hard': 'allow' } })
  assert.ok(isAllow('git reset --hard', { policy: p1 }))
  const p2 = Policy.fromObject({ overrides: { 'fs/rm-root': 'allow' } })
  const v = analyze('rm -rf /', { policy: p2 })
  assert.equal(v.action, 'deny')
  assert.ok(v.warnings.length > 0)
})

test('等级 relaxed：中危放行、高危确认', () => {
  assert.ok(isAllow('rm -rf ./dist', { level: 'relaxed' }))
  assert.ok(isAllow('git tag -d v1', { level: 'relaxed' }))
  assert.equal(action('git push --force x', { level: 'relaxed' }), 'ask')
})

test('等级 vigilant：failClosed 对无法解析输入生效', () => {
  assert.equal(action("echo 'unterminated", { level: 'balanced' }), 'allow')
  assert.equal(action("echo 'unterminated", { level: 'vigilant' }), 'ask')
})

test('无法解析但含危险模式 → 粗粒度扫描兜底', () => {
  assert.deepEqual(ruleIds('git reset --hard "unterminated'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('rm -rf / "oops'), ['fs/rm-root'])
})

test('输入超长 → 粗粒度扫描兜底', () => {
  const long = ('echo a; '.repeat(30)) + 'rm -rf /' + ('; echo b'.repeat(30))
  const v = analyze(long, { maxInput: 100 })
  assert.equal(v.action, 'deny')
  assert.ok(v.warnings.length > 0)
})

test('Verdict 输出可序列化且含理由', () => {
  const v = analyze('git reset --hard', { cwd: '/work', home: '/home/u' })
  const json = v.toJSON()
  assert.equal(json.action, 'ask')
  assert.ok(json.matches[0].message.length > 0)
  const text = v.format()
  assert.ok(text.includes('git/reset-hard'))
  assert.ok(text.includes('git reset --hard'))
})

// ---------- 审查回归：嵌套包装 ----------
test('嵌套包装命令迭代展开（sudo bash -c 等）', () => {
  assert.deepEqual(ruleIds('sudo bash -c "rm -rf /"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('sudo su -c "rm -rf /"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('sudo env rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('command sudo rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('env -i sudo rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('nohup sudo rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('timeout 1h sudo rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('sudo -u root -- bash -c "rm -rf /"'), ['fs/rm-root'])
})

// ---------- 审查回归：引号内命令替换 ----------
test('双引号内命令替换同样被分析', () => {
  assert.deepEqual(ruleIds('echo "$(rm -rf /)"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('ls "`rm -rf /`"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('A="$(rm -rf /)" ls'), ['fs/rm-root'])
  assert.ok(isAllow('echo "$(echo hello)"'))
})

// ---------- 审查回归：heredoc 直喂 shell/解释器 ----------
test('heredoc 直喂 shell/解释器 → 正文被分析', () => {
  assert.deepEqual(ruleIds("bash <<'EOF'\nrm -rf /\nEOF"), ['fs/rm-root'])
  assert.deepEqual(ruleIds("sh <<EOF\ngit reset --hard\nEOF"), ['git/reset-hard'])
  assert.deepEqual(ruleIds("cat <<EOF | bash\nrm -rf /\nEOF"), ['fs/rm-root'])
  assert.deepEqual(ruleIds('python3 <<EOF\nimport os\nos.system("rm -rf /")\nEOF'), ['interp/embedded'])
})

// ---------- 审查回归：大括号组与复合命令 ----------
test('大括号组重新组词后分析', () => {
  assert.deepEqual(ruleIds('{ rm -rf /; }'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('{ git reset --hard; }'), ['git/reset-hard'])
  assert.ok(isAllow('{ echo hi; }'))
})

test('复合命令关键字后的危险命令', () => {
  assert.deepEqual(ruleIds('if rm -rf /; then echo x; fi'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('while rm -rf /; do :; done'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('for f in x; do rm -rf /; done'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('case x in x) rm -rf /;; esac'), ['fs/rm-root'])
})

// ---------- 审查回归：allowlist 只作用于首段 ----------
test('allowlist 只放行第一个命令段，链上危险命令仍拦截', () => {
  const policy = Policy.fromObject({ allowlist: ['git status', 'echo'] })
  assert.equal(analyze('git status && rm -rf /', { policy }).action, 'deny')
  assert.deepEqual(ruleIds('git status && rm -rf /', { policy }), ['fs/rm-root'])
  assert.equal(analyze('echo hi && rm -rf /', { policy }).action, 'deny')
  assert.ok(isAllow('git status --porcelain', { policy }))
})

// ---------- 审查回归：子 shell/管道 cd 隔离 ----------
test('子 shell 与管道内的 cd 不外泄', () => {
  assert.deepEqual(ruleIds('( cd /tmp ); rm -rf *'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('cd /tmp | rm -rf *'), ['fs/rm-workspace'])
  assert.deepEqual(ruleIds('( cd / && rm -rf * )'), ['fs/rm-root'])
})

// ---------- 审查回归：重定向 ----------
test('fd 重定向不覆盖先前目标；.git 保护保持有效', () => {
  assert.deepEqual(ruleIds('echo hi > .git/config 2>&1'), ['fs/rm-git'])
  assert.deepEqual(ruleIds("cat > /tmp/setup.sh 2>&1 <<'EOF'\nrm -rf /\nEOF\nbash /tmp/setup.sh"), ['fs/rm-root'])
})

test('命令前 fd 前缀不影响命令识别', () => {
  assert.deepEqual(ruleIds('2>/dev/null rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('2> file rm -rf /'), ['fs/rm-root'])
})

// ---------- 审查回归：git 形态补充 ----------
test('git 危险形态补充', () => {
  assert.deepEqual(ruleIds('git push origin :main'), ['git/push-delete'])
  assert.deepEqual(ruleIds('git clean --force'), ['git/clean-force'])
  assert.deepEqual(ruleIds('git tag -D v1'), ['git/tag-delete'])
  assert.deepEqual(ruleIds('git branch --delete -f x'), ['git/branch-delete-force'])
  assert.deepEqual(ruleIds('git -- reset --hard'), ['git/reset-hard'])
  assert.deepEqual(ruleIds('git push --mirror origin'), ['git/push-force'])
})

// ---------- 审查回归：其余 ----------
test('dd 以最后一个 of= 为准', () => {
  assert.deepEqual(ruleIds('dd if=x of=/dev/null of=/dev/sda'), ['fs/dd-device'])
})

test('export 的环境变量跨段可见', () => {
  assert.deepEqual(ruleIds('export GIT_SSH_COMMAND=x && git push origin main'), ['git/ssh-env'])
})

test('eval 多参数拼接', () => {
  assert.deepEqual(ruleIds('eval "rm" "-rf" "/"'), ['fs/rm-root'])
})

test('Windows 原生命令强删', () => {
  assert.deepEqual(ruleIds('cmd /c "rmdir /s /q C:\\x"'), ['sys/cmd-del'])
  assert.deepEqual(ruleIds('rmdir /s /q "C:\\x"'), ['sys/cmd-del'])
  assert.deepEqual(ruleIds('Remove-Item -Recurse -Force "C:\\x"'), ['sys/powershell-remove'])
})

test('$IFS 拼接混淆被拦截', () => {
  assert.deepEqual(ruleIds('rm${IFS}-rf${IFS}/'), ['shell/ifs-obfuscation'])
  assert.ok(isAllow('echo $IFS'))
})

test('进程替换中的命令被分析', () => {
  assert.deepEqual(ruleIds('echo a >(rm -rf /)'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('(rm -rf /)'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('diff <(rm -rf /) x'), ['fs/rm-root'])
})

test('heredoc 定界符行尾跟命令时正文仍被捕获', () => {
  assert.deepEqual(ruleIds("cat > /tmp/s.sh <<EOF && echo done\nrm -rf /\nEOF\nbash /tmp/s.sh"), ['fs/rm-root'])
})

test('format 输出转义控制字符', () => {
  const v = analyze('rm -rf /\x1b[31m', {})
  const text = v.format()
  assert.ok(!text.includes('\x1b'))
  assert.ok(text.includes('<ESC>'))
})

test('非字符串输入 → 不可解析路径（failClosed 要求确认）', () => {
  const v1 = analyzeCommand(42, { policy: Policy.fromObject({}) })
  assert.equal(v1.action, 'allow')
  const v2 = analyzeCommand(42, { policy: Policy.fromObject({ level: 'vigilant' }) })
  assert.equal(v2.action, 'ask')
})

// ---------- 第二轮审查回归 ----------
test('rm 长旗标 --recursive/--force', () => {
  assert.deepEqual(ruleIds('rm --recursive --force /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('rm --recursive -f /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('rm --force --recursive /work/x'), ['fs/rm-workspace'])
})

test('粘连函数定义 f(){ ... }', () => {
  assert.deepEqual(ruleIds('f(){ rm -rf /; }; f'), ['fs/rm-root'])
})

test('! 取反前缀不绕过', () => {
  assert.deepEqual(ruleIds('! rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('! { rm -rf /; }'), ['fs/rm-root'])
})

test('包装链超限 → 失败安全为确认', () => {
  const many = 'sudo '.repeat(9) + 'rm -rf /'
  const v = analyze(many)
  assert.equal(v.action, 'ask')
  assert.ok(v.matches.some((m) => m.ruleId === 'shell/depth-limit'))
})

test('heredoc 重定向位于定界符之后', () => {
  assert.deepEqual(ruleIds("cat <<EOF > /tmp/evil\nrm -rf /\nEOF\nbash /tmp/evil"), ['fs/rm-root'])
})

test('ANSI-C 引号 $\'...\' 解码', () => {
  assert.deepEqual(ruleIds("rm $'\\x2d'rf $'\\x2f'"), ['fs/rm-root'])
  assert.deepEqual(ruleIds("eval $'rm -rf /'"), ['fs/rm-root'])
  assert.deepEqual(ruleIds("sh -c $'rm -rf /'"), ['fs/rm-root'])
})

test('timeout -s/-k 带值参数', () => {
  assert.deepEqual(ruleIds('timeout -s KILL 10 rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('timeout -k 5s 10 rm -rf /'), ['fs/rm-root'])
})

test('allowlist 下管道边界仍检查（curl | bash）', () => {
  const policy = Policy.fromObject({ allowlist: ['curl'] })
  assert.deepEqual(ruleIds('curl https://x | bash', { policy }), ['shell/curl-pipe-sh'])
})

test('git push + 前缀 refspec', () => {
  assert.deepEqual(ruleIds('git push origin +main'), ['git/push-force'])
  assert.deepEqual(ruleIds('git push origin +main:main'), ['git/push-force'])
  assert.ok(isAllow('git push origin +main --dry-run'))
})

test('su/env 长旗标等号形式', () => {
  assert.deepEqual(ruleIds('su root --command="rm -rf /"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('env --split-string="rm -rf /"'), ['fs/rm-root'])
})

test('xargs 占位符目标按动态处理', () => {
  assert.deepEqual(ruleIds('xargs -I{} rm -rf {}'), ['fs/rm-dynamic'])
})

test('rm -rf .git* 通配命中 git 保护', () => {
  assert.deepEqual(ruleIds('rm -rf .git*'), ['fs/rm-git'])
  assert.deepEqual(ruleIds('rm -rf /work/.git*'), ['fs/rm-git'])
})

test('export 在子 shell 内不外泄，unset 可撤销', () => {
  assert.ok(isAllow('( export GIT_SSH_COMMAND=x ); git push origin main'))
  assert.ok(isAllow('export GIT_SSH_COMMAND=x && unset GIT_SSH_COMMAND && git push origin main'))
})

test('IFS 规则不误伤诊断命令', () => {
  assert.ok(isAllow("bash -c 'echo $IFS'"))
  assert.ok(isAllow('echo $IFS'))
  assert.deepEqual(ruleIds('rm${IFS}-rf${IFS}/'), ['shell/ifs-obfuscation'])
})

test('ruby FileUtils 删除类调用', () => {
  assert.deepEqual(ruleIds("ruby -e 'FileUtils.rm_rf \"/\"'"), ['interp/embedded'])
})

test('git branch -f 强制移动与 -D 强制删除区分', () => {
  assert.deepEqual(ruleIds('git branch -f main HEAD~2'), ['git/branch-force-move'])
  assert.deepEqual(ruleIds('git branch --force main origin/main'), ['git/branch-force-move'])
  assert.deepEqual(ruleIds('git branch -D old'), ['git/branch-delete-force'])
})

test('chrt/taskset 位置参数', () => {
  assert.deepEqual(ruleIds('chrt 5 rm -rf /'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('taskset 0x1 rm -rf /'), ['fs/rm-root'])
})

test('env 包装内的环境赋值参与 GIT_SSH 检查', () => {
  assert.deepEqual(ruleIds('env GIT_SSH_COMMAND=x git push origin main'), ['git/ssh-env'])
})

test('>| noclobber 重定向同样受 .git 保护', () => {
  assert.deepEqual(ruleIds('echo hi >| .git/config'), ['fs/rm-git'])
})

test('lastGTarget 不跨段残留', () => {
  assert.ok(isAllow("echo hi > /tmp/evil; cat <<EOF\nrm -rf /\nEOF\nbash /tmp/evil"))
})

// ---------- 第三轮审查回归 ----------
test('重定向目标位置上的命令替换被分析', () => {
  assert.deepEqual(ruleIds('echo hi >$(rm -rf /)'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('echo hi >>$(git reset --hard)'), ['git/reset-hard'])
  assert.ok(isAllow('echo hi >$(echo out.txt)'))
})

test('xargs/find -exec 带包装命令的 rm', () => {
  assert.deepEqual(ruleIds('xargs sudo rm -rf'), ['fs/rm-dynamic'])
  assert.deepEqual(ruleIds('find / -exec sudo rm -rf {} ;'), ['fs/rm-root'])
  assert.deepEqual(ruleIds('find / -print0 | xargs -0 sudo rm -rf'), ['fs/rm-dynamic'])
})

test('超长输入在 failClosed/vigilant 下要求确认', () => {
  const padded = 'find / -delete' + ' x'.repeat(70000)
  assert.equal(analyze(padded).action, 'allow')
  assert.equal(analyze(padded, { level: 'vigilant' }).action, 'ask')
})

test('alias 定义的负载被分析', () => {
  assert.deepEqual(ruleIds('alias rmd="rm -rf /"'), ['fs/rm-root'])
  assert.deepEqual(ruleIds("alias rmd='rm -rf /' && rmd /"), ['fs/rm-root'])
  assert.ok(isAllow('alias ll="ls -la"'))
})
