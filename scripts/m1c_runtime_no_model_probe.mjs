/** No model/session boot. Exercise only frozen local runtime primitives. */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync, mkdirSync, realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const [program, scratch] = process.argv.slice(2)
assert(program && scratch && process.argv.length === 4)
const root = realpathSync(program)
const work = realpathSync(scratch)
assert(!work.startsWith(root + '/') && work !== root)
assert.equal(process.execPath, join(root, '.runtime-node/bin/node'))
assert.equal(process.env.NODE_OPTIONS, undefined)
assert.equal(process.env.LD_LIBRARY_PATH, undefined)
const anchor = join(root, 'apps/cli/package.json')
const require = createRequire(anchor)
const load = async (name) => import(pathToFileURL(require.resolve(name)))
const boot = await load('@deepseek-ai/dsh-app-boot')
const homes = [join(work, 'home-a'), join(work, 'home-b')]
const required = new Set()
const visit = (rows) => {
  for (const row of rows) {
    if (row && typeof row === 'object' && typeof row.name === 'string' && row.name.startsWith('@')) {
      required.add(row.name)
    }
    if (Array.isArray(row)) visit(row)
    else if (row && typeof row === 'object') visit(Object.values(row))
  }
}
for (const home of homes) {
  mkdirSync(home)
  boot.healProfilesModuleFallback(anchor, home)
  const profile = boot.loadProfile('dsh', 'headless', anchor, home)
  assert(profile.layers.length > 0)
  for (const layer of profile.layers) {
    assert(layer.packageDir.startsWith(root + '/'))
    assert(layer.patchPath.startsWith(root + '/'))
    readFileSync(layer.patchPath)
    visit(layer.patches)
  }
  writeFileSync(join(home, 'isolation-marker'), home)
}
assert.notEqual(readFileSync(join(homes[0], 'isolation-marker'), 'utf8'),
                readFileSync(join(homes[1], 'isolation-marker'), 'utf8'))
// Resolve modules without instantiating Cordis plugins or provider objects.
const profileRequire = createRequire(join(homes[0], 'profiles/headless/package.json'))
for (const name of required) assert(profileRequire.resolve(name).startsWith(root + '/'))
const subprocessRequire = createRequire(profileRequire.resolve('@deepseek-ai/dsh-subprocess-local'))
const pty = subprocessRequire('node-pty')
await new Promise((done, reject) => {
  const timer = setTimeout(() => reject(new Error('PTY_TIMEOUT')), 5000)
  const terminal = pty.spawn('/bin/sh', ['-c', 'printf DSH_PTY_PROBE'],
                             { cwd: work, env: { PATH: '/usr/bin:/bin' } })
  let text = ''
  terminal.onData((data) => { text += data })
  terminal.onExit(({ exitCode }) => {
    clearTimeout(timer)
    try { assert.equal(exitCode, 0); assert(text.includes('DSH_PTY_PROBE')); done() }
    catch (error) { reject(error) }
  })
})
// FFI load only; no provider, model, Win32 calls, or task commands.
subprocessRequire('koffi')
const sandboxRequire = createRequire(profileRequire.resolve('@deepseek-ai/dsh-sandbox-local'))
const landlock = await import(pathToFileURL(sandboxRequire.resolve('@deepseek-ai/node-addon-landlock-run')))
assert.notEqual(landlock.probe(), 'unusable')
const rgRequire = createRequire(profileRequire.resolve('@deepseek-ai/dsh-tool-fs-search'))
const { rgPath } = rgRequire('@vscode/ripgrep')
assert(realpathSync(rgPath).startsWith(root + '/'))
assert.equal(spawnSync(rgPath, ['--version'], { cwd: work }).status, 0)
const fsPath = join(work, 'fs-probe')
writeFileSync(fsPath, 'DSH_FS_PROBE')
assert.equal(readFileSync(fsPath, 'utf8'), 'DSH_FS_PROBE')
console.log(JSON.stringify({schema_version: 'm1c_runtime_probe_v1', status: 'PASS',
  profile_resolution: 'PASS', plugin_resolution: 'PASS', resolved_plugin_count: required.size,
  native_load: 'PASS', pty: 'PASS', filesystem: 'PASS', sandbox: 'PASS', isolation: 'PASS',
  provider_path_reached: false, provider_requests: 0, model_sessions: 0}))
