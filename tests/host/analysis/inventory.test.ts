import { describe, expect, it } from 'vitest'
import { buildInventory } from '../../../src/host/analysis/inventory.ts'
import { snapshotOf } from './helpers.ts'

describe('buildInventory', () => {
  it('counts languages sorted by file count', () => {
    const inventory = buildInventory(
      snapshotOf({
        'a.ts': 'aaaa',
        'b.ts': 'bb',
        'c.py': 'c',
        'tests/d.ts': 'd',
      }),
    )
    expect(inventory.languages).toEqual([
      { language: 'typescript', files: 3, bytes: 7 },
      { language: 'python', files: 1, bytes: 1 },
    ])
    expect(inventory.testFiles).toBe(1)
  })

  it('lists manifests including Kubernetes YAML and Terraform', () => {
    const inventory = buildInventory(
      snapshotOf({
        'package.json': '{}',
        'web/pnpm-lock.yaml': 'lockfileVersion: 9.0',
        'requirements-prod.txt': 'flask',
        Dockerfile: 'FROM node:22',
        'docker-compose.override.yml': 'services: {}',
        'infra/main.tf': 'resource "x" "y" {}',
        'k8s/deploy.yaml': 'apiVersion: apps/v1\nkind: Deployment\n',
        'config/app.yaml': 'name: app\n',
        'go.mod': 'module x',
        'Cargo.toml': '[package]',
        'build.gradle.kts': '',
        'src/index.ts': '',
      }),
    )
    expect(inventory.manifests).toEqual([
      'Cargo.toml',
      'Dockerfile',
      'build.gradle.kts',
      'docker-compose.override.yml',
      'go.mod',
      'infra/main.tf',
      'k8s/deploy.yaml',
      'package.json',
      'requirements-prod.txt',
      'web/pnpm-lock.yaml',
    ])
  })

  it('detects JavaScript frameworks from package.json dependencies', () => {
    const inventory = buildInventory(
      snapshotOf({
        'package.json': JSON.stringify({
          dependencies: { express: '^4', '@prisma/client': '5', jsonwebtoken: '9', '@remix-run/node': '2' },
          devDependencies: { helmet: '7', '@nestjs/core': '10' },
        }),
        'apps/web/package.json': JSON.stringify({ dependencies: { next: '14', 'next-auth': '4' } }),
        'broken/package.json': '{ not json',
      }),
    )
    expect(inventory.frameworks).toEqual([
      'express',
      'helmet',
      'jsonwebtoken',
      'nestjs',
      'next',
      'next-auth',
      'prisma',
      'remix',
    ])
  })

  it('detects Python frameworks from requirements, pyproject, and Pipfile', () => {
    const inventory = buildInventory(
      snapshotOf({
        'requirements.txt': '# comment\nFlask==3.0.0\n-r other.txt\nSQLAlchemy>=2\n',
        'svc/pyproject.toml': [
          '[project]',
          'name = "svc"',
          'dependencies = [',
          '  "fastapi[all]>=0.110",',
          '  "pydantic>=2",',
          ']',
          '[tool.poetry.dependencies]',
          'python = "^3.11"',
          'celery = "^5"',
          '[tool.black]',
          'django = "not a dep"',
        ].join('\n'),
        Pipfile: '[packages]\nPyJWT = "*"\n',
      }),
    )
    expect(inventory.frameworks).toEqual(['celery', 'fastapi', 'flask', 'pydantic', 'pyjwt', 'sqlalchemy'])
  })
})
