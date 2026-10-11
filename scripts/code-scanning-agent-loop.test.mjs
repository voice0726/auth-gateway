import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  alertKey,
  analysisMatchesPullRequest,
  canRetryAlert,
  evaluatePullRequest,
  main,
  normalizeResult,
  selectAlert,
} from './code-scanning-agent-loop.mjs';

const shaA = 'a'.repeat(40);
const shaB = 'b'.repeat(40);

function alert(number, sha = shaA) {
  return { number, most_recent_instance: { commit_sha: sha } };
}

test('selection skips terminal history and any matching open alert PR', () => {
  const alerts = [alert(1), alert(2), alert(3)];
  const ledger = {
    alerts: {
      [alertKey(alerts[0])]: { status: 'false_positive', attempts: 1 },
      [alertKey(alerts[1])]: { status: 'blocked', attempts: 3 },
    },
  };
  const openPRs = [{ body: `<!-- code-scanning-alert:3 analysis:${shaA} -->` }];
  assert.equal(selectAlert(alerts, ledger, openPRs), undefined);
});

test('selection resumes an interrupted or retrying alert under the attempt cap', () => {
  const candidate = alert(7);
  const ledger = { alerts: { [alertKey(candidate)]: { status: 'processing', attempts: 1 } } };
  assert.equal(selectAlert([candidate], ledger, []), candidate);
  ledger.alerts[alertKey(candidate)].attempts = 3;
  assert.equal(selectAlert([candidate], ledger, []), undefined);
});

test('agent result must match the selected alert and include a PR for vulnerabilities', () => {
  const expected = { number: 9, analysis_sha: shaA };
  assert.equal(normalizeResult(JSON.stringify({ status: 'false_positive', alert_number: 9, analysis_sha: shaA, evidence: 'Guard guarantees the input is a fixed enum.' }), expected).status, 'false_positive');
  assert.equal(normalizeResult(JSON.stringify({ status: 'false_positive', alert_number: 9, analysis_sha: shaB, evidence: 'Evidence.' }), expected).status, 'retry');
  assert.equal(normalizeResult(JSON.stringify({ status: 'vulnerability', alert_number: 9, analysis_sha: shaA, evidence: 'Reachable input.' }), expected).status, 'retry');
});

test('initial scan and PR repair share a two-attempt limit', () => {
  assert.equal(canRetryAlert(1), true);
  assert.equal(canRetryAlert(2), false);
});

test('PR verification requires an analysis for the current head or merge commit', () => {
  assert.equal(analysisMatchesPullRequest(shaA, shaA, shaB), true);
  assert.equal(analysisMatchesPullRequest(shaB, shaA, shaB), true);
  assert.equal(analysisMatchesPullRequest(shaB, shaA, 'c'.repeat(40)), false);
  assert.equal(analysisMatchesPullRequest(undefined, shaA, shaB), false);
});

test('main-open alert is verified only by a current fixed PR instance and successful CI', () => {
  const result = evaluatePullRequest({
    checkRuns: [{ id: 1, name: 'test', status: 'completed', conclusion: 'success', app: { id: 7 } }],
    statuses: { state: 'pending', total_count: 0, statuses: [] },
    instance: { state: 'fixed', commit_sha: shaA },
    headSha: shaA,
  });
  assert.equal(result.disposition, 'verified');
});

test('stale PR analysis remains pending even when the old instance was fixed', () => {
  const result = evaluatePullRequest({
    checkRuns: [{ id: 1, name: 'test', status: 'completed', conclusion: 'success' }],
    statuses: { state: 'success', total_count: 1, statuses: [{ id: 3, context: 'legacy', state: 'success' }] },
    instance: { state: 'fixed', commit_sha: shaB },
    headSha: shaA,
  });
  assert.equal(result.disposition, 'pending');
});

test('a confirmed CI failure can trigger repair before a PR analysis arrives', () => {
  const result = evaluatePullRequest({
    checkRuns: [{ id: 1, name: 'test', status: 'completed', conclusion: 'failure' }],
    statuses: { state: 'failure', total_count: 1, statuses: [{ id: 3, context: 'test', state: 'failure' }] },
    instance: null,
    headSha: shaA,
  });
  assert.deepEqual(result, { disposition: 'repair', reason: 'ci_failure', instanceCurrent: false, ciPassed: false });
});

test('the newest run for a check replaces an older failure and pending status contexts block verification', () => {
  const checks = [
    { id: 10, name: 'test', status: 'completed', conclusion: 'failure', app: { id: 7 }, external_id: 'job' },
    { id: 11, name: 'test', status: 'completed', conclusion: 'success', app: { id: 7 }, external_id: 'job' },
  ];
  const verified = evaluatePullRequest({ checkRuns: checks, statuses: { state: 'pending', total_count: 0, statuses: [] }, instance: { state: 'fixed', commit_sha: shaA }, headSha: shaA });
  assert.equal(verified.disposition, 'verified');
  const pending = evaluatePullRequest({ checkRuns: checks, statuses: { state: 'pending', total_count: 1, statuses: [{ id: 2, context: 'required', state: 'pending' }] }, instance: { state: 'fixed', commit_sha: shaA }, headSha: shaA });
  assert.equal(pending.disposition, 'pending');
});

test('prepare persists a processing reservation before handing off an alert', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-loop-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  let ledgerBody;
  const alertFixture = { number: 12, html_url: 'https://github.test/example/repo/security/code-scanning/12', rule: { id: 'sample/rule', severity: 'warning' }, most_recent_instance: { commit_sha: shaA, message: { text: 'fixture alert' }, location: { path: 'auth/session.go', start_line: 10 } } };
  globalThis.fetch = async (url, options = {}) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/contents/ledger.json') && options.method !== 'PUT') return new Response('missing', { status: 404 });
    if (path.endsWith('/code-scanning/alerts')) return Response.json([alertFixture]);
    if (path.endsWith('/pulls')) return Response.json([]);
    if (path.endsWith('/git/ref/heads/main')) return Response.json({ object: { sha: shaB } });
    if (path.endsWith('/git/refs')) return Response.json({ ref: 'refs/heads/automation/code-scanning-ledger' }, { status: 201 });
    if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
      ledgerBody = JSON.parse(options.body);
      return Response.json({ content: { sha: 'ledger-file-sha' } }, { status: 201 });
    }
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan',
    RUNNER_TEMP: temp,
  });
  try {
    await main('prepare');
    const outputs = await readFile(outputPath, 'utf8');
    const saved = JSON.parse(Buffer.from(ledgerBody.content, 'base64').toString('utf8'));
    assert.match(outputs, /has_work=true/);
    assert.deepEqual(saved.alerts[`12@${shaA}`], {
      status: 'processing', attempts: 1, evidence: 'Agent attempt reserved before execution.', updated_at: saved.alerts[`12@${shaA}`].updated_at,
    });
    assert.match(saved.alerts[`12@${shaA}`].updated_at, /^\d{4}-/);
    await main('cleanup-prompt');
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('scheduled prepare verifies an open main alert from a current fixed PR instance', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-verify-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `22@${shaA}`;
  const ledger = { version: 1, alerts: { [key]: { status: 'processing_followup', attempts: 2, pull_request: 44, followup_sha: shaA, last_followup_sha: null } }, updated_at: null };
  let savedLedger = ledger;
  const prHead = { ref: `security/code-scanning/alert-22-${shaA}`, sha: shaA, repo: { full_name: 'example/repo' } };
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname;
    if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
      savedLedger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-ledger-sha' } });
    }
    if (path.endsWith('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(savedLedger)).toString('base64'), sha: 'ledger-sha' });
    if (path.endsWith('/code-scanning/alerts') && parsed.searchParams.get('ref') === 'refs/heads/main') {
      return Response.json([{ number: 22, state: 'open', most_recent_instance: { commit_sha: shaA } }]);
    }
    if (path.endsWith('/pulls')) return Response.json([{ number: 44, state: 'open', draft: true, base: { ref: 'main' }, head: prHead, merge_commit_sha: shaB, html_url: 'https://github.test/example/repo/pull/44', body: `<!-- code-scanning-alert:22 analysis:${shaA} -->` }]);
    if (path.endsWith('/check-runs')) return Response.json({ check_runs: [{ id: 1, name: 'test', status: 'completed', conclusion: 'success', app: { id: 7 } }] });
    if (path.endsWith('/status')) return Response.json({ state: 'pending', total_count: 0, statuses: [] });
    if (path.endsWith('/instances')) return Response.json([{ ref: 'refs/pull/44/merge', state: 'fixed', commit_sha: shaA, location: { path: 'auth/session.go', start_line: 9 } }]);
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan', RUNNER_TEMP: temp,
  });
  try {
    await main('prepare');
    assert.equal(savedLedger.alerts[key].status, 'verified');
    assert.equal(savedLedger.alerts[key].analyzed_sha, shaA);
    assert.match(await readFile(outputPath, 'utf8'), /has_work=false/);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('scheduled prepare reserves same-PR repair when CI fails before CodeQL analysis arrives', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-repair-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `23@${shaA}`;
  let savedLedger = { version: 1, alerts: { [key]: { status: 'pending_pr', attempts: 1, pull_request: 45 } }, updated_at: null };
  const prHead = { ref: `security/code-scanning/alert-23-${shaA}`, sha: shaB, repo: { full_name: 'example/repo' } };
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname;
    if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
      savedLedger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-ledger-sha' } });
    }
    if (path.endsWith('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(savedLedger)).toString('base64'), sha: 'ledger-sha' });
    if (path.endsWith('/code-scanning/alerts') && parsed.searchParams.get('ref') === 'refs/heads/main') return Response.json([{ number: 23, state: 'open', most_recent_instance: { commit_sha: shaA } }]);
    if (path.endsWith('/pulls')) return Response.json([{ number: 45, state: 'open', draft: true, base: { ref: 'main' }, head: prHead, merge_commit_sha: 'c'.repeat(40), html_url: 'https://github.test/example/repo/pull/45', body: `<!-- code-scanning-alert:23 analysis:${shaA} -->` }]);
    if (path.endsWith('/check-runs')) return Response.json({ check_runs: [{ id: 2, name: 'test', status: 'completed', conclusion: 'failure', app: { id: 7 } }] });
    if (path.endsWith('/status')) return Response.json({ state: 'failure', total_count: 1, statuses: [{ id: 3, context: 'test', state: 'failure' }] });
    if (path.endsWith('/instances')) return Response.json([]);
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan', RUNNER_TEMP: temp,
  });
  try {
    await main('prepare');
    assert.equal(savedLedger.alerts[key].status, 'processing_followup');
    assert.equal(savedLedger.alerts[key].followup_sha, shaB);
    assert.equal(savedLedger.alerts[key].attempts, 2);
    assert.match(await readFile(outputPath, 'utf8'), /task_mode=followup/);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('prepare recovers a validated PR created before an interrupted initial result', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-recover-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `24@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing', attempts: 1 } }, updated_at: null };
  const pr = { number: 46, state: 'open', draft: true, base: { ref: 'main' }, head: { ref: `security/code-scanning/alert-24-${shaA}`, sha: shaB, repo: { full_name: 'example/repo' } }, merge_commit_sha: 'c'.repeat(40), body: `<!-- code-scanning-alert:24 analysis:${shaA} -->` };
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname;
    if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-ledger-sha' } });
    }
    if (path.endsWith('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-sha' });
    if (path.endsWith('/code-scanning/alerts')) return Response.json([{ number: 24, state: 'open', most_recent_instance: { commit_sha: shaA } }]);
    if (path.endsWith('/pulls')) return Response.json([pr]);
    if (path.endsWith('/check-runs')) return Response.json({ check_runs: [{ id: 2, name: 'test', status: 'completed', conclusion: 'success' }] });
    if (path.endsWith('/status')) return Response.json({ state: 'success', total_count: 1, statuses: [{ id: 4, context: 'test', state: 'success' }] });
    if (path.endsWith('/instances')) return Response.json([]);
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, { GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB, GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan', RUNNER_TEMP: temp });
  try {
    await main('prepare');
    assert.equal(ledger.alerts[key].status, 'pending_pr');
    assert.equal(ledger.alerts[key].pull_request, 46);
    assert.equal(ledger.alerts[key].attempts, 1);
    assert.match(await readFile(outputPath, 'utf8'), /has_work=false/);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('follow-up preserves an advanced PR head when the agent output is empty', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-followup-result-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `25@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing_followup', attempts: 2, pull_request: 47, followup_sha: shaA } }, updated_at: null };
  const pr = { number: 47, head: { sha: shaB } };
  globalThis.fetch = async (url, options = {}) => {
    if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-ledger-sha' } });
    }
    if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-sha' });
    if (url.endsWith('/pulls/47')) return Response.json(pr);
    if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath,
    EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 25, analysis_sha: shaA })).toString('base64'),
    AGENT_RESULT_B64: '', TASK_MODE: 'followup', PR_NUMBER: '47', PR_HEAD_SHA: shaA,
    FOLLOWUP_ATTEMPT: '2',
  });
  try {
    await main('finalize');
    assert.equal(ledger.alerts[key].status, 'pending_pr');
    assert.equal(ledger.alerts[key].attempts, 2);
    assert.equal(ledger.alerts[key].head_sha, shaB);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('attempt two recovers a matching PR when the initial agent output is empty', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-final-recovery-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `26@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing', attempts: 2 } }, updated_at: null };
  const pr = { number: 48, state: 'open', draft: true, base: { ref: 'main' }, head: { ref: `security/code-scanning/alert-26-${shaA}`, sha: shaB, repo: { full_name: 'example/repo' } }, body: `<!-- code-scanning-alert:26 analysis:${shaA} -->` };
  globalThis.fetch = async (url, options = {}) => {
    if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-file-sha' } });
    }
    if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-file-sha' });
    if (url.endsWith('/pulls?state=open&base=main&per_page=100&page=1')) return Response.json([pr]);
    if (url.endsWith('/pulls/48')) return Response.json(pr);
    if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath,
    EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 26, analysis_sha: shaA, attempt: 2 })).toString('base64'),
    AGENT_RESULT_B64: '', TASK_MODE: 'scan',
  });
  try {
    await main('finalize');
    assert.equal(ledger.alerts[key].status, 'pending_pr');
    assert.equal(ledger.alerts[key].attempts, 2);
    assert.equal(ledger.alerts[key].pull_request, 48);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});

test('an empty Pullfrog output is persisted as retrying or blocked at the attempt limit', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-finalize-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  let ledger = { version: 1, alerts: { [`14@${shaA}`]: { status: 'processing', attempts: 2 } }, updated_at: null };
  const ledgerSha = 'ledger-file-sha';
  globalThis.fetch = async (url, options = {}) => {
    if (options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-file-sha' } });
    }
    if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: ledgerSha });
    if (url.includes('/pulls?state=open&base=main')) return Response.json([]);
    if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath,
    EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 14, analysis_sha: shaA, attempt: 2 })).toString('base64'),
    AGENT_RESULT_B64: '', TASK_MODE: 'scan',
  });
  try {
    await main('finalize');
    assert.equal(ledger.alerts[`14@${shaA}`].status, 'blocked');
    assert.match(ledger.alerts[`14@${shaA}`].evidence, /valid JSON/i);
    assert.match(await readFile(outputPath, 'utf8'), /retry=false/);
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    await rm(temp, { recursive: true, force: true });
  }
});
