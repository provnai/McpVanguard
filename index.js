#!/usr/bin/env node

/**
 * McpVanguard Node.js Bridge
 * Satisfies the "Built with Node.js" preference for Claude Desktop Extensions
 * while maintaining the high-assurance Python security core.
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

function resolvePythonCommand() {
  if (process.env.VANGUARD_PYTHON) {
    return process.env.VANGUARD_PYTHON;
  }

  const venv = process.env.VIRTUAL_ENV;
  if (venv) {
    const venvPython = process.platform === 'win32'
      ? path.join(venv, 'Scripts', 'python.exe')
      : path.join(venv, 'bin', 'python');
    if (fs.existsSync(venvPython)) {
      return venvPython;
    }
  }

  const repoLocalPython = process.platform === 'win32'
    ? path.join(__dirname, '.venv', 'Scripts', 'python.exe')
    : path.join(__dirname, '.venv', 'bin', 'python');
  if (fs.existsSync(repoLocalPython)) {
    return repoLocalPython;
  }

  return process.platform === 'win32' ? 'python' : 'python3';
}

const pythonCmd = resolvePythonCommand();

const child = spawn(pythonCmd, ['-m', 'core.cli', 'start', ...args], {
  cwd: __dirname,
  stdio: 'inherit',
  env: {
    ...process.env,
    PYTHONPATH: __dirname
  }
});

child.on('exit', (code) => {
  process.exit(code ?? 0);
});

child.on('error', (err) => {
  console.error('[McpVanguard Bridge] Failed to start Python core:', err.message);
  console.error('Set VANGUARD_PYTHON or ensure Python 3.11+ is installed and available.');
  process.exit(1);
});
