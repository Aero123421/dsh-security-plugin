import { afterEach, describe, expect, it, vi } from 'vitest'
import { copyText, downloadFile, safeFilename } from '../../src/client/download.ts'

afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('downloadFile', () => {
  it('saves the report through a temporary <a download> and revokes the object URL', async () => {
    vi.useFakeTimers()
    const blobs: Blob[] = []
    const create = vi.spyOn(URL, 'createObjectURL').mockImplementation(blob => {
      blobs.push(blob as Blob)
      return 'blob:report-1'
    })
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clicked: HTMLAnchorElement[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this)
      expect(this.isConnected).toBe(true)
    })

    downloadFile({ filename: 'security-report.sarif', mime: 'application/sarif+json', content: '{"runs":[]}' })

    expect(create).toHaveBeenCalledTimes(1)
    expect(blobs[0]?.type).toContain('application/sarif+json')
    expect(await blobs[0]?.text()).toBe('{"runs":[]}')
    expect(clicked).toHaveLength(1)
    expect(clicked[0]?.download).toBe('security-report.sarif')
    expect(clicked[0]?.getAttribute('href')).toBe('blob:report-1')
    expect(clicked[0]?.isConnected).toBe(false)
    expect(revoke).not.toHaveBeenCalled()
    vi.runAllTimers()
    expect(revoke).toHaveBeenCalledWith('blob:report-1')
  })

  it('sanitizes Host-provided filenames', () => {
    expect(safeFilename('../../etc/passwd')).toBe('passwd')
    expect(safeFilename('..')).toBe('security-report.txt')
    expect(safeFilename('a:b*c?.md')).toBe('a-b-c-.md')
    expect(safeFilename('')).toBe('security-report.txt')
    expect(safeFilename(undefined)).toBe('security-report.txt')
    expect(safeFilename('report.md')).toBe('report.md')
  })
})

describe('copyText', () => {
  it('uses the async clipboard when available', async () => {
    const writeText = vi.fn(async () => {})
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    await expect(copyText('hello')).resolves.toBe(true)
    expect(writeText).toHaveBeenCalledWith('hello')
    vi.unstubAllGlobals()
  })

  it('falls back to a hidden textarea + execCommand', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn(async () => Promise.reject(new Error('denied'))) } })
    const exec = vi.fn(() => true)
    ;(document as unknown as { execCommand: unknown }).execCommand = exec
    await expect(copyText('fallback')).resolves.toBe(true)
    expect(exec).toHaveBeenCalledWith('copy')
    expect(document.querySelector('textarea')).toBeNull()
    vi.unstubAllGlobals()
  })
})
