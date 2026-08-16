import test from 'node:test'
import assert from 'node:assert/strict'
import { tokenize } from '../src/tokenizer.js'

function wordsOf(input) {
  return tokenize(input).tokens.filter((t) => t.type === 'word').map((t) => t.value)
}
function opsOf(input) {
  return tokenize(input).tokens.filter((t) => t.type === 'operator').map((t) => t.value)
}

test('基础分词：空白分隔与普通操作符', () => {
  assert.deepEqual(wordsOf('rm -rf /tmp/x'), ['rm', '-rf', '/tmp/x'])
  assert.deepEqual(opsOf('a && b || c; d | e & f'), ['&&', '||', ';', '|', '&'])
  assert.deepEqual(opsOf('a |& b'), ['|&'])
})

test('引号：单引号内一切字面', () => {
  assert.deepEqual(wordsOf(`echo "a b" 'c d' e`), ['echo', 'a b', 'c d', 'e'])
  assert.deepEqual(wordsOf("echo 'a\\b'"), ['echo', 'a\\b'])
  assert.deepEqual(wordsOf("echo 'a'\\''b'"), ['echo', "a'b"])
})

test('引号：双引号内反斜杠仅对 $ ` " \\ 生效', () => {
  assert.deepEqual(wordsOf('echo "a\\b"'), ['echo', 'a\\b'])
  assert.deepEqual(wordsOf('echo "a\\$b"'), ['echo', 'a$b'])
  assert.deepEqual(wordsOf('echo "a\\"b"'), ['echo', 'a"b'])
})

test('反斜杠转义在引号外生效', () => {
  assert.deepEqual(wordsOf('echo a\\ b'), ['echo', 'a b'])
  assert.deepEqual(wordsOf('echo a\\;b'), ['echo', 'a;b'])
})

test('重定向与 fd 前缀', () => {
  assert.deepEqual(wordsOf('cmd > out.txt 2>&1'), ['cmd', 'out.txt', '2', '1'])
  assert.deepEqual(opsOf('cmd >> out.txt'), ['>>'])
  assert.deepEqual(opsOf('cmd <<< data'), ['<<<'])
  assert.deepEqual(opsOf('cat < in.txt'), ['<'])
  assert.deepEqual(opsOf('exec 3>&-'), ['>&'])
})

test('注释：行首与命令后', () => {
  assert.deepEqual(wordsOf('echo hi # comment\nls'), ['echo', 'hi', 'ls'])
  assert.deepEqual(wordsOf('echo foo#bar'), ['echo', 'foo#bar'])
})

test('heredoc：捕获正文直到定界符', () => {
  const r = tokenize('cat > out.txt <<EOF\nhello world\nEOF\nls')
  assert.equal(r.ok, true)
  const heredocs = r.tokens.filter((t) => t.type === 'heredoc')
  assert.equal(heredocs.length, 1)
  assert.equal(heredocs[0].value, 'hello world')
  assert.equal(heredocs[0].delimiter, 'EOF')
  assert.ok(r.tokens.some((t) => t.type === 'word' && t.value === 'ls'))
})

test('heredoc：引号定界符与 <<- 缩进', () => {
  const r1 = tokenize("cat <<'EOT'\nline one\nEOT")
  assert.equal(r1.tokens.find((t) => t.type === 'heredoc').quoted, true)
  assert.equal(r1.tokens.find((t) => t.type === 'heredoc').value, 'line one')
  const r2 = tokenize('cat <<-EOF\n\tindented line\n\tEOF')
  assert.equal(r2.tokens.find((t) => t.type === 'heredoc').value, 'indented line')
})

test('heredoc：未闭合时剩余部分视为正文', () => {
  const r = tokenize('cat <<EOF\nbody without end')
  assert.equal(r.ok, true)
  assert.equal(r.tokens.find((t) => t.type === 'heredoc').value, 'body without end')
})

test('命令替换与反引号被提取为 substitution', () => {
  const r = tokenize('ls $(echo hi; rm -rf /) `pwd`')
  const subs = r.tokens.filter((t) => t.type === 'substitution').map((t) => t.value)
  assert.deepEqual(subs, ['echo hi; rm -rf /', 'pwd'])
})

test('$(( )) 算术与 ${} / $x 展开不产生 substitution', () => {
  const r = tokenize('echo $((1+2)) ${HOME} $x')
  assert.equal(r.tokens.filter((t) => t.type === 'substitution').length, 0)
  assert.deepEqual(wordsOf('echo $((1+2)) ${HOME} $x'), ['echo', '$((1+2))', '${HOME}', '$x'])
})

test('嵌套命令替换与带引号内容', () => {
  const r = tokenize('echo $(echo "$(pwd)")')
  const subs = r.tokens.filter((t) => t.type === 'substitution').map((t) => t.value)
  assert.deepEqual(subs, ['echo "$(pwd)"'])
})

test('未闭合单引号 → 失败', () => {
  const r = tokenize("echo 'abc")
  assert.equal(r.ok, false)
  assert.equal(r.error, 'unterminated-quote')
})

test('子 shell 括号是操作符', () => {
  assert.deepEqual(opsOf('( cd /tmp && ls )'), ['(', '&&', ')'])
})

test('输入超长 → 失败', () => {
  const r = tokenize('x'.repeat(100), { maxLen: 50 })
  assert.equal(r.ok, false)
  assert.equal(r.error, 'input-too-long')
})

test('空输入与纯空白', () => {
  const r = tokenize('')
  assert.equal(r.ok, true)
  assert.deepEqual(r.tokens, [])
  const r2 = tokenize('   \n\t ')
  assert.equal(r2.ok, true)
  assert.deepEqual(r2.tokens, [])
})

test('换行作为命令分隔', () => {
  assert.deepEqual(wordsOf('a\nb'), ['a', 'b'])
})

test('赋值形式被保留为普通词', () => {
  assert.deepEqual(wordsOf('A=1 B="x y" cmd'), ['A=1', 'B=x y', 'cmd'])
  assert.deepEqual(wordsOf('curl https://example.com/x'), ['curl', 'https://example.com/x'])
})
