import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PINNED_INTERFOLD_COMMIT = 'c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a';
export const CIRCUIT_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_DIR = resolve(CIRCUIT_DIR, '../..');
export const SOURCE_DIR = resolve(REPO_DIR, '.tools/interfold-noir');

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

export function assertPinnedSource() {
  if (git('-C', SOURCE_DIR, 'rev-parse', 'HEAD') !== PINNED_INTERFOLD_COMMIT) {
    throw new Error('Noir dependency is not the pinned Interfold commit');
  }
  if (git('-C', SOURCE_DIR, 'status', '--porcelain', '--', 'circuits/lib')) {
    throw new Error('Pinned Interfold Noir library has local changes');
  }
  if (!existsSync(resolve(SOURCE_DIR, 'circuits/lib/Nargo.toml'))) {
    throw new Error('Pinned Noir library checkout is incomplete');
  }
}

export function setup() {
  if (!existsSync(SOURCE_DIR)) {
    mkdirSync(SOURCE_DIR, { recursive: true });
    git('-C', SOURCE_DIR, 'init');
    git('-C', SOURCE_DIR, 'remote', 'add', 'origin', 'https://github.com/theinterfold/interfold');
    git('-C', SOURCE_DIR, 'sparse-checkout', 'init', '--cone');
    git('-C', SOURCE_DIR, 'sparse-checkout', 'set', 'circuits/lib');
    git('-C', SOURCE_DIR, 'fetch', '--depth=1', 'origin', PINNED_INTERFOLD_COMMIT);
    git('-C', SOURCE_DIR, 'checkout', '--detach', 'FETCH_HEAD');
  }
  assertPinnedSource();
  return { interfoldCommit: PINNED_INTERFOLD_COMMIT, source: SOURCE_DIR };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(setup()));
}
