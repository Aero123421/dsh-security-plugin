import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  compareGlibcVersion,
  detectHostGlibcVersion,
  detectHostLibc,
  glibcSatisfiesPython,
  libcFamilyFromReport,
  parseGlibcVersion,
  pluginPackageRoot,
  PYTHON_DYNAMIC_LANGUAGE,
  PYTHON_GRAMMAR_TARGETS,
  PYTHON_LINUX_GLIBC_MIN,
  pythonPrebuildName,
  vendoredPythonLibrary,
} from '../../../src/host/analysis/python-grammar.ts'

describe('vendored Python grammar', () => {
  it('ships a native library for every published target', () => {
    const root = pluginPackageRoot()
    expect(root).toBeTruthy()
    for (const target of PYTHON_GRAMMAR_TARGETS) {
      const path = join(root!, 'vendor', 'tree-sitter-python', 'prebuilds', `prebuild-${target}`, 'parser.so')
      expect(existsSync(path), path).toBe(true)
    }
    expect(PYTHON_DYNAMIC_LANGUAGE.languageSymbol).toBe('tree_sitter_python')
    expect(PYTHON_DYNAMIC_LANGUAGE.expandoChar).toBe('\u00b5')
    expect(PYTHON_DYNAMIC_LANGUAGE.extensions).toEqual(['py'])
  })

  it('resolves the library for this process when a target exists', () => {
    const name = pythonPrebuildName(process.platform, process.arch)
    const path = vendoredPythonLibrary()
    if (name) {
      expect(path).toMatch(new RegExp(`prebuild-${name}/parser.so$`))
      expect(existsSync(path!)).toBe(true)
    } else {
      expect(path).toBeUndefined()
    }
  })

  it('returns undefined for platforms the package does not ship', () => {
    expect(pythonPrebuildName('freebsd', 'x64')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'ia32', 'glibc')).toBeUndefined()
    expect(vendoredPythonLibrary('freebsd', 'x64')).toBeUndefined()
    expect(vendoredPythonLibrary('win32', 'arm64')).toBeUndefined()
  })

  it('does not select a glibc Linux parser when glibcVersionRuntime is absent', () => {
    expect(libcFamilyFromReport(undefined)).toBe('musl')
    expect(libcFamilyFromReport({})).toBe('musl')
    expect(libcFamilyFromReport({ header: {} })).toBe('musl')
    expect(libcFamilyFromReport({ header: { glibcVersionRuntime: '' } })).toBe('musl')
    expect(libcFamilyFromReport({ header: { glibcVersionRuntime: '2.39' } })).toBe('glibc')
    expect(pythonPrebuildName('linux', 'x64', 'musl')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'arm64', 'musl')).toBeUndefined()
    expect(vendoredPythonLibrary('linux', 'x64', 'musl')).toBeUndefined()
    expect(vendoredPythonLibrary('linux', 'arm64', 'musl')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '2.39')).toBe('Linux-X64')
    expect(vendoredPythonLibrary('linux', 'x64', 'glibc', '2.39')).toMatch(/prebuild-Linux-X64\/parser\.so$/)
    // macOS and Windows files are not glibc objects. A musl label does not hide them.
    expect(pythonPrebuildName('darwin', 'arm64', 'musl')).toBe('macOS-ARM64')
    expect(vendoredPythonLibrary('darwin', 'arm64', 'musl')).toMatch(/prebuild-macOS-ARM64\/parser\.so$/)
  })

  it('treats this Linux process as glibc when Node reports a glibc runtime', () => {
    if (process.platform !== 'linux') return
    const report = process.report.getReport() as { header?: { glibcVersionRuntime?: string } }
    expect(typeof report.header?.glibcVersionRuntime).toBe('string')
    expect(detectHostLibc()).toBe('glibc')
    expect(detectHostGlibcVersion()).toBe(report.header?.glibcVersionRuntime)
    expect(pythonPrebuildName('linux', process.arch)).toBe(process.arch === 'x64' ? 'Linux-X64' : 'Linux-ARM64')
  })

  it('compares glibc versions numerically', () => {
    expect(parseGlibcVersion('2.9')).toEqual([2, 9])
    expect(parseGlibcVersion('2.17.0')).toEqual([2, 17, 0])
    expect(parseGlibcVersion('')).toBeUndefined()
    expect(parseGlibcVersion('2.17-rc')).toBeUndefined()
    expect(compareGlibcVersion([2, 9], [2, 17])).toBe(-1)
    expect(compareGlibcVersion([2, 17], [2, 9])).toBe(1)
    expect(compareGlibcVersion([2, 17], [2, 17, 0])).toBe(0)
    expect(glibcSatisfiesPython('Linux-ARM64', '2.9')).toBe(false)
    expect(glibcSatisfiesPython('Linux-ARM64', '2.17')).toBe(true)
    expect(glibcSatisfiesPython('Linux-X64', '2.2.5')).toBe(true)
    expect(glibcSatisfiesPython('Linux-X64', '2.2.4')).toBe(false)
    expect(glibcSatisfiesPython('Linux-X64', undefined)).toBe(false)
    expect(glibcSatisfiesPython('Linux-ARM64', '')).toBe(false)
    expect(PYTHON_LINUX_GLIBC_MIN['Linux-X64']).toEqual([2, 2, 5])
    expect(PYTHON_LINUX_GLIBC_MIN['Linux-ARM64']).toEqual([2, 17])
  })

  it('does not select a Linux parser older than that file’s GLIBC symbol version', () => {
    // Linux x64 parser.so: GLIBC_2.2.5. Linux arm64 parser.so: GLIBC_2.17.
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '2.2.5')).toBe('Linux-X64')
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '2.2.4')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '2.2')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '2.9')).toBe('Linux-X64')
    expect(vendoredPythonLibrary('linux', 'x64', 'glibc', '2.2.4')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'arm64', 'glibc', '2.17')).toBe('Linux-ARM64')
    expect(pythonPrebuildName('linux', 'arm64', 'glibc', '2.17.0')).toBe('Linux-ARM64')
    expect(pythonPrebuildName('linux', 'arm64', 'glibc', '2.16')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'arm64', 'glibc', '2.9')).toBeUndefined()
    expect(vendoredPythonLibrary('linux', 'arm64', 'glibc', '2.16')).toBeUndefined()
    expect(vendoredPythonLibrary('linux', 'arm64', 'glibc', '2.17')).toMatch(/prebuild-Linux-ARM64\/parser\.so$/)
    expect(pythonPrebuildName('linux', 'x64', 'glibc', 'nope')).toBeUndefined()
    expect(pythonPrebuildName('linux', 'x64', 'glibc', '')).toBeUndefined()
    expect(pythonPrebuildName('win32', 'x64', 'glibc', '2.9')).toBe('Windows-X64')
    expect(pythonPrebuildName('linux', 'arm64', 'musl', '2.39')).toBeUndefined()
    expect(pythonPrebuildName('darwin', 'arm64', 'glibc', '2.9')).toBe('macOS-ARM64')
  })
})
