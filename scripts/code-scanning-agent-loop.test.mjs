import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
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
const mainInstance = { ref: 'refs/heads/main', state: 'open', analysis_key: 'codeql.yml:scan', environment: '{}', category: 'go' };

function prInstance(state, sha = shaA, ref = 'refs/pull/1/merge', context = mainInstance) {
  return { ...context, ref, state, commit_sha: sha };
}

function parseGithubOutput(content) {
  const values = [];
  const lines = content.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const block = lines[index].match(/^([^=<>]+)<<(.+)$/);
    if (block) {
      const body = [];
      while (++index < lines.length && lines[index] !== block[2]) body.push(lines[index]);
      assert.notEqual(index, lines.length, `missing delimiter for ${block[1]}`);
      values.push([block[1], body.join('\n')]);
      continue;
    }
    const single = lines[index].match(/^([^=<>]+)=(.*)$/);
    if (single) values.push([single[1], single[2]]);
  }
  return values;
}

function alert(number, sha = shaA) {
  return { number, most_recent_instance: { commit_sha: sha } };
}

function alertPR(number, sha = shaA, overrides = {}) {
  return {
    number: 70,
    state: 'open',
    draft: true,
    base: { ref: 'main' },
    head: { ref: `security/code-scanning/alert-${number}-${sha}`, repo: { full_name: 'example/repo' } },
    body: `<!-- code-scanning-alert:${number} analysis:${sha} -->`,
    ...overrides,
  };
}

test('selection skips terminal history and any matching open alert PR', () => {
  const alerts = [alert(1), alert(2), alert(3)];
  const ledger = {
    alerts: {
      [alertKey(alerts[0])]: { status: 'false_positive', attempts: 1 },
      [alertKey(alerts[1])]: { status: 'blocked', attempts: 3 },
    },
  };
  const openPRs = [alertPR(3)];
  assert.equal(selectAlert(alerts, ledger, openPRs, 'example/repo'), undefined);
});

test('selection resumes an interrupted or retrying alert under the attempt cap', () => {
  const candidate = alert(7);
  const ledger = { alerts: { [alertKey(candidate)]: { status: 'processing', attempts: 1 } } };
  assert.equal(selectAlert([candidate], ledger, [], 'example/repo'), candidate);
  ledger.alerts[alertKey(candidate)].attempts = 3;
  assert.equal(selectAlert([candidate], ledger, [], 'example/repo'), undefined);
});

test('human-closed history suppresses all later analysis SHAs while ordinary blocked history does not', () => {
  const current = alert(8, shaB);
  const ledger = { alerts: {
    [`8@${shaA}`]: { status: 'blocked', human_closed: true, attempts: 1 },
    [`9@${shaA}`]: { status: 'blocked', attempts: 2 },
  } };
  assert.equal(selectAlert([current], ledger, [], 'example/repo'), undefined);
  const newAnalysisAfterBlocked = alert(9, shaB);
  assert.equal(selectAlert([newAnalysisAfterBlocked], ledger, [], 'example/repo'), newAnalysisAfterBlocked);
});

test('a valid open PR for an older analysis SHA suppresses the same alert number', () => {
  const current = alert(12, shaB);
  assert.equal(selectAlert([current], { alerts: {} }, [alertPR(12, shaA)], 'example/repo'), undefined);
});

test('only a matching same-repository draft PR suppresses an alert', () => {
  const candidate = alert(10, shaA);
  const invalidPRs = [
    alertPR(10, shaA, { head: { ref: `security/code-scanning/alert-10-${shaA}`, repo: { full_name: 'fork/repo' } } }),
    alertPR(10, shaA, { head: { ref: 'feature/unrelated', repo: { full_name: 'example/repo' } } }),
    alertPR(11, shaA),
    alertPR(10, shaA, { draft: false }),
  ];
  for (const pr of invalidPRs) assert.equal(selectAlert([candidate], { alerts: {} }, [pr], 'example/repo'), candidate);
});

test('agent result must match the selected alert and include a PR for vulnerabilities', () => {
  const expected = { number: 9, analysis_sha: shaA };
  assert.equal(normalizeResult(JSON.stringify({ status: 'false_positive', alert_number: 9, analysis_sha: shaA, evidence: 'Guard guarantees the input is a fixed enum.' }), expected).status, 'false_positive');
  const mismatch = normalizeResult(JSON.stringify({ status: 'false_positive', alert_number: 9, analysis_sha: shaB, evidence: 'Evidence.' }), expected);
  assert.equal(mismatch.status, 'retry');
  assert.match(mismatch.evidence, /did not match the selected alert and analysis/);
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
    mainInstances: [mainInstance],
    prInstances: [prInstance('fixed')],
    prRef: 'refs/pull/1/merge',
    headSha: shaA,
  });
  assert.equal(result.disposition, 'verified');
});

test('stale PR analysis remains pending even when the old instance was fixed', () => {
  const result = evaluatePullRequest({
    checkRuns: [{ id: 1, name: 'test', status: 'completed', conclusion: 'success' }],
    statuses: { state: 'success', total_count: 1, statuses: [{ id: 3, context: 'legacy', state: 'success' }] },
    mainInstances: [mainInstance],
    prInstances: [prInstance('fixed', shaB)],
    prRef: 'refs/pull/1/merge',
    headSha: shaA,
  });
  assert.equal(result.disposition, 'pending');
});

test('a confirmed CI failure can trigger repair before a PR analysis arrives', () => {
  const result = evaluatePullRequest({
    checkRuns: [{ id: 1, name: 'test', status: 'completed', conclusion: 'failure' }],
    statuses: { state: 'failure', total_count: 1, statuses: [{ id: 3, context: 'test', state: 'failure' }] },
    mainInstances: [mainInstance],
    prInstances: [],
    prRef: 'refs/pull/1/merge',
    headSha: shaA,
  });
  assert.deepEqual(result, { disposition: 'repair', reason: 'ci_failure', instanceCurrent: false, ciPassed: false });
});

test('the newest run for a check replaces an older failure and pending status contexts block verification', () => {
  const checks = [
    { id: 10, name: 'test', status: 'completed', conclusion: 'failure', app: { id: 7 }, external_id: 'old-job-id' },
    { id: 11, name: 'test', status: 'completed', conclusion: 'success', app: { id: 7 }, external_id: 'rerun-job-id' },
  ];
  const verified = evaluatePullRequest({ checkRuns: checks, statuses: { state: 'pending', total_count: 0, statuses: [] }, mainInstances: [mainInstance], prInstances: [prInstance('fixed')], prRef: 'refs/pull/1/merge', headSha: shaA });
  assert.equal(verified.disposition, 'verified');
  const pending = evaluatePullRequest({ checkRuns: checks, statuses: { state: 'pending', total_count: 1, statuses: [{ id: 2, context: 'required', state: 'pending' }] }, mainInstances: [mainInstance], prInstances: [prInstance('fixed')], prRef: 'refs/pull/1/merge', headSha: shaA });
  assert.equal(pending.disposition, 'pending');
});

test('startup_failure is a confirmed failure for test and non-test checks', () => {
  for (const name of ['test', 'CodeQL']) {
    const result = evaluatePullRequest({
      checkRuns: [{ id: 20, name, status: 'completed', conclusion: 'startup_failure', app: { id: 7 } }],
      mainInstances: [mainInstance],
      prInstances: [],
      prRef: 'refs/pull/1/merge',
      headSha: shaA,
    });
    assert.equal(result.disposition, 'repair', name);
    assert.equal(result.reason, 'ci_failure', name);
  }
});

test('all open main contexts need current fixed PR results, independent of API order', () => {
  const secondContext = { ...mainInstance, analysis_key: 'codeql.yml:scan', environment: '{"language":"javascript"}', category: 'javascript' };
  const mainInstances = [mainInstance, secondContext];
  const fixed = prInstance('fixed', shaA, 'refs/pull/1/merge', mainInstance);
  const open = prInstance('open', shaB, 'refs/pull/1/merge', secondContext);
  for (const prInstances of [[fixed, open], [open, fixed]]) {
    const result = evaluatePullRequest({ checkRuns: [], mainInstances, prInstances, prRef: 'refs/pull/1/merge', headSha: shaA, mergeSha: shaB });
    assert.equal(result.disposition, 'repair');
    assert.equal(result.reason, 'alert_open');
  }
  for (const prInstances of [[fixed, prInstance('open')], [prInstance('open'), fixed]]) {
    const result = evaluatePullRequest({ checkRuns: [], mainInstances: [mainInstance], prInstances, prRef: 'refs/pull/1/merge', headSha: shaA });
    assert.equal(result.disposition, 'repair');
  }
  const stale = evaluatePullRequest({ checkRuns: [], mainInstances, prInstances: [fixed, prInstance('fixed', 'c'.repeat(40), 'refs/pull/1/merge', secondContext)], prRef: 'refs/pull/1/merge', headSha: shaA, mergeSha: shaB });
  assert.equal(stale.disposition, 'pending');
  const absent = evaluatePullRequest({ checkRuns: [], mainInstances, prInstances: [fixed], prRef: 'refs/pull/1/merge', headSha: shaA, mergeSha: shaB });
  assert.equal(absent.disposition, 'pending');
  const ciSuccess = [{ id: 1, name: 'test', status: 'completed', conclusion: 'success' }];
  const mixedShaResults = [
    [prInstance('open', shaA), prInstance('fixed', shaB)],
    [prInstance('fixed', shaB), prInstance('open', shaA)],
    [prInstance('open', shaB), prInstance('fixed', shaA)],
    [prInstance('fixed', shaA), prInstance('open', shaB)],
  ];
  for (const prInstances of mixedShaResults) {
    const result = evaluatePullRequest({ checkRuns: ciSuccess, mainInstances: [mainInstance], prInstances, prRef: 'refs/pull/1/merge', headSha: shaA, mergeSha: shaB });
    assert.equal(result.disposition, 'repair');
    assert.equal(result.reason, 'alert_open');
  }
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
    if (path.endsWith('/instances') && parsed.searchParams.get('ref') === 'refs/heads/main') return Response.json([mainInstance]);
    if (path.endsWith('/instances')) return Response.json([prInstance('fixed', shaA, 'refs/pull/44/merge')]);
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
    if (path.endsWith('/instances') && parsed.searchParams.get('ref') === 'refs/heads/main') return Response.json([mainInstance]);
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

test('prepare reconciles closed PRs across ledger states without recreating their alert', async () => {
  for (const [status, merged] of [['pending_pr', false], ['verified', false], ['blocked', false], ['verified', true]]) {
    const temp = await mkdtemp(join(tmpdir(), 'code-scanning-closed-pr-'));
    const outputPath = join(temp, 'output');
    const previousFetch = globalThis.fetch;
    const previousEnv = { ...process.env };
    const key = `31@${shaA}`;
    const mainSha = merged ? shaA : shaB;
    let ledger = { version: 1, alerts: { [key]: { status, attempts: 1, pull_request: 56 } }, updated_at: null };
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname;
      if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
        ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
        return Response.json({ content: { sha: 'next-ledger-sha' } });
      }
      if (path.endsWith('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-sha' });
      if (path.endsWith('/code-scanning/alerts')) return Response.json([{ number: 31, state: 'open', most_recent_instance: { commit_sha: mainSha } }]);
      if (path.endsWith('/pulls')) return Response.json([]);
      if (path.endsWith('/pulls/56')) return Response.json({ number: 56, state: 'closed', merged, merged_at: merged ? '2026-10-11T00:00:00Z' : null });
      throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
    };
    Object.assign(process.env, {
      GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
      GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan',
    });
    try {
      await main('prepare');
      assert.equal(ledger.alerts[key].status, merged ? 'merged' : 'blocked');
      assert.equal(ledger.alerts[key].human_closed, !merged);
      if (!merged) assert.match(ledger.alerts[key].evidence, /closed without merging/);
      assert.match(await readFile(outputPath, 'utf8'), /has_work=false/);
    } finally {
      globalThis.fetch = previousFetch;
      for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
      Object.assign(process.env, previousEnv);
      await rm(temp, { recursive: true, force: true });
    }
  }
});

test('prepare records explicit blocked reasons for tracked PRs that become invalid', async () => {
  const valid = alertPR(33, shaA, { number: 57, head: { ...alertPR(33, shaA).head, sha: shaB } });
  const cases = [
    { pr: { ...valid, draft: false }, reason: /marked ready/ },
    { pr: { ...valid, body: '' }, reason: /marker/ },
    { pr: { ...valid, head: { ...valid.head, ref: 'security/code-scanning/alert-33-wrong' } }, reason: /branch/ },
    { pr: { ...valid, head: { ...valid.head, repo: { full_name: 'fork/repo' } } }, reason: /not in this repository/ },
  ];
  for (const { pr, reason } of cases) {
    const temp = await mkdtemp(join(tmpdir(), 'code-scanning-invalid-tracked-pr-'));
    const outputPath = join(temp, 'output');
    const previousFetch = globalThis.fetch;
    const previousEnv = { ...process.env };
    const key = `33@${shaA}`;
    let ledger = { version: 1, alerts: { [key]: { status: 'pending_pr', attempts: 1, pull_request: 57 } }, updated_at: null };
    globalThis.fetch = async (url, options = {}) => {
      const path = new URL(url).pathname;
      if (path.endsWith('/contents/ledger.json') && options.method === 'PUT') {
        ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
        return Response.json({ content: { sha: 'next-ledger-sha' } });
      }
      if (path.endsWith('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-sha' });
      if (path.endsWith('/code-scanning/alerts')) return Response.json([{ number: 33, state: 'open', most_recent_instance: { commit_sha: shaA } }]);
      if (path.endsWith('/pulls')) return Response.json([pr]);
      throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
    };
    Object.assign(process.env, {
      GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
      GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath, REQUESTED_MODE: 'scan',
    });
    try {
      await main('prepare');
      assert.equal(ledger.alerts[key].status, 'blocked');
      assert.match(ledger.alerts[key].evidence, reason);
      assert.match(await readFile(outputPath, 'utf8'), /has_work=false/);
    } finally {
      globalThis.fetch = previousFetch;
      for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
      Object.assign(process.env, previousEnv);
      await rm(temp, { recursive: true, force: true });
    }
  }
});

test('follow-up preserves an advanced PR head when the agent output is empty', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-followup-result-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `25@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing_followup', attempts: 2, pull_request: 47, followup_sha: shaA } }, updated_at: null };
  const pr = {
    number: 47, state: 'open', draft: true, base: { ref: 'main' },
    head: { ref: `security/code-scanning/alert-25-${shaA}`, sha: shaB, repo: { full_name: 'example/repo' } },
    body: `<!-- code-scanning-alert:25 analysis:${shaA} -->`,
  };
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

test('follow-up finalization blocks a PR invalidated after prepare and records human closure', async () => {
  const valid = alertPR(62, shaA, { number: 62 });
  const cases = [
    { pr: { ...valid, draft: false }, reason: /marked ready/, humanClosed: false },
    { pr: { ...valid, body: 'marker removed' }, reason: /marker does not match/, humanClosed: false },
    { pr: { ...valid, state: 'closed', merged: false, merged_at: null }, reason: /closed without merging/, humanClosed: true },
  ];
  for (const { pr, reason, humanClosed } of cases) {
    const temp = await mkdtemp(join(tmpdir(), 'code-scanning-followup-invalidated-'));
    const previousFetch = globalThis.fetch;
    const previousEnv = { ...process.env };
    const key = `62@${shaA}`;
    let ledger = { version: 1, alerts: { [key]: { status: 'processing_followup', attempts: 2, pull_request: 62, followup_sha: shaA } }, updated_at: null };
    globalThis.fetch = async (url, options = {}) => {
      if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
        ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
        return Response.json({ content: { sha: 'next-ledger-sha' } });
      }
      if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-file-sha' });
      if (url.endsWith('/pulls/62')) return Response.json(pr);
      if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
      throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
    };
    Object.assign(process.env, {
      GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
      GITHUB_API_URL: 'https://api.github.test', GITHUB_STEP_SUMMARY: join(temp, 'summary'),
      EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 62, analysis_sha: shaA })).toString('base64'),
      AGENT_RESULT_B64: '', TASK_MODE: 'followup', PR_NUMBER: '62', PR_HEAD_SHA: shaA,
      FOLLOWUP_ATTEMPT: '2',
    });
    try {
      await main('finalize');
      assert.equal(ledger.alerts[key].status, 'blocked');
      assert.equal(Boolean(ledger.alerts[key].human_closed), humanClosed);
      assert.match(ledger.alerts[key].evidence, reason);
    } finally {
      globalThis.fetch = previousFetch;
      for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
      Object.assign(process.env, previousEnv);
      await rm(temp, { recursive: true, force: true });
    }
  }
});

test('attempt two recovers a matching PR when the initial agent output is empty', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-final-recovery-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `26@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing', attempts: 2 } }, updated_at: null };
  const invalidPR = { number: 49, state: 'open', draft: true, base: { ref: 'main' }, head: { ref: 'security/code-scanning/alert-26-wrong', sha: shaB, repo: { full_name: 'example/repo' } }, body: `<!-- code-scanning-alert:26 analysis:${shaA} -->` };
  const pr = { number: 48, state: 'open', draft: true, base: { ref: 'main' }, head: { ref: `security/code-scanning/alert-26-${shaA}`, sha: shaB, repo: { full_name: 'example/repo' } }, body: `<!-- code-scanning-alert:26 analysis:${shaA} -->` };
  globalThis.fetch = async (url, options = {}) => {
    if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-file-sha' } });
    }
    if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-file-sha' });
    if (url.endsWith('/pulls?state=open&base=main&per_page=100&page=1')) return Response.json([invalidPR, pr]);
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

test('retry evidence with newlines and CR cannot inject GitHub output keys', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'code-scanning-output-injection-'));
  const outputPath = join(temp, 'output');
  const previousFetch = globalThis.fetch;
  const previousEnv = { ...process.env };
  const key = `61@${shaA}`;
  let ledger = { version: 1, alerts: { [key]: { status: 'processing', attempts: 1 } }, updated_at: null };
  const evidence = 'retry=false\r\nhas_work=true\nsummary=forged';
  globalThis.fetch = async (url, options = {}) => {
    if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
      ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
      return Response.json({ content: { sha: 'next-ledger-sha' } });
    }
    if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-file-sha' });
    if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
    throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
  };
  Object.assign(process.env, {
    GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
    GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath,
    EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 61, analysis_sha: shaA, attempt: 1 })).toString('base64'),
    AGENT_RESULT: JSON.stringify({ status: 'retry', alert_number: 61, analysis_sha: shaA, evidence }),
    TASK_MODE: 'scan', ATTEMPT: '1',
  });
  try {
    await main('normalize');
    const normalized = parseGithubOutput(await readFile(outputPath, 'utf8')).find(([name]) => name === 'result_b64')?.[1];
    assert.ok(normalized);
    process.env.AGENT_RESULT_B64 = normalized;
    await main('finalize');
    const values = parseGithubOutput(await readFile(outputPath, 'utf8'));
    assert.deepEqual(values.filter(([name]) => name === 'retry').map(([, value]) => value), ['true', 'true']);
    assert.deepEqual(values.filter(([name]) => name === 'summary').map(([, value]) => value), ['retry=false\nhas_work=true\nsummary=forged']);
    assert.equal(values.some(([name]) => name === 'has_work'), false);
    assert.equal(ledger.alerts[key].status, 'retrying');
    assert.equal(ledger.alerts[key].evidence, evidence);
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

test('normalized retry evidence survives finalization for empty, invalid, and incomplete output', async () => {
  const cases = [
    ['', 'Pullfrog result was not valid JSON.'],
    ['{invalid', 'Pullfrog result was not valid JSON.'],
    [JSON.stringify({ status: 'false_positive', alert_number: 32, analysis_sha: shaA }), 'Pullfrog result did not include evidence.'],
  ];
  for (const [raw, evidence] of cases) {
    const temp = await mkdtemp(join(tmpdir(), 'code-scanning-normalized-retry-'));
    const outputPath = join(temp, 'output');
    const previousFetch = globalThis.fetch;
    const previousEnv = { ...process.env };
    const key = `32@${shaA}`;
    let ledger = { version: 1, alerts: { [key]: { status: 'processing', attempts: 2 } }, updated_at: null };
    globalThis.fetch = async (url, options = {}) => {
      if (url.includes('/contents/ledger.json') && options.method === 'PUT') {
        ledger = JSON.parse(Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
        return Response.json({ content: { sha: 'next-file-sha' } });
      }
      if (url.includes('/contents/ledger.json')) return Response.json({ content: Buffer.from(JSON.stringify(ledger)).toString('base64'), sha: 'ledger-file-sha' });
      if (url.includes('/pulls?state=open&base=main')) return Response.json([]);
      if (url.includes('/actions/workflows/code-scanning-agent-loop.yml/dispatches')) return new Response(null, { status: 204 });
      throw new Error(`Unexpected fixture request ${options.method ?? 'GET'} ${url}`);
    };
    Object.assign(process.env, {
      GH_TOKEN: 'fixture-token', GITHUB_REPOSITORY: 'example/repo', GITHUB_SHA: shaB,
      GITHUB_API_URL: 'https://api.github.test', GITHUB_OUTPUT: outputPath,
      EXPECTED_ALERT: Buffer.from(JSON.stringify({ number: 32, analysis_sha: shaA, attempt: 2 })).toString('base64'),
      AGENT_RESULT: raw, TASK_MODE: 'scan',
    });
    try {
      await main('normalize');
      const normalized = (await readFile(outputPath, 'utf8')).match(/^result_b64=(.+)$/m)?.[1];
      assert.ok(normalized);
      process.env.AGENT_RESULT_B64 = normalized;
      await main('finalize');
      assert.equal(ledger.alerts[key].status, 'blocked');
      assert.equal(ledger.alerts[key].evidence, evidence);
    } finally {
      globalThis.fetch = previousFetch;
      for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
      Object.assign(process.env, previousEnv);
      await rm(temp, { recursive: true, force: true });
    }
  }
});
