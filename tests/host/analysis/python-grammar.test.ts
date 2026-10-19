import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  pluginPackageRoot,
  PYTHON_DYNAMIC_LANGUAGE,
  PYTHON_GRAMMAR_TARGETS,
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
    expect(pythonPrebuildName('linux', 'ia32')).toBeUndefined()
    expect(vendoredPythonLibrary('freebsd', 'x64')).toBeUndefined()
    expect(vendoredPythonLibrary('win32', 'arm64')).toBeUndefined()
  })
})
