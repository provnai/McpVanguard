#!/usr/bin/env node

/**
 * McpVanguard Node.js Bridge
 * Satisfies the "Built with Node.js" preference for Claude Desktop Extensions
 * while maintaining the high-assurance Python security core.
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

// Check if we are running in a venv or need to find python
const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

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
  console.error('Ensure Python 3.11+ is installed and core/cli.py exists.');
  process.exit(1);
});
