// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { config } from '../config'

const execFileAsync = promisify(execFile)

export interface ChangeEntry {
  commit: string
  author: string
  date: string
  subject: string
}

/** Recent commits that touched one catalog file, newest first. */
export async function recentChanges(name: string, limit = 20): Promise<ChangeEntry[]> {
  const { stdout } = await execFileAsync('git', ['log', `-n${limit}`, '--format=%H%x09%an%x09%aI%x09%s', '--', name], {
    cwd: config.repoDir,
    timeout: 5000,
    maxBuffer: 1024 * 1024,
  })
  return stdout
    .split('\n')
    .filter(line => line !== '')
    .map(line => {
      const [commit = '', author = '', date = '', subject = ''] = line.split('\t')
      return { commit, author, date, subject }
    })
}
