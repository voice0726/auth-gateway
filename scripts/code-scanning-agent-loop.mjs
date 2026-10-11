#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { appendFile } from 'node:fs/promises';

const apiVersion = '2022-11-28';
const ledgerBranch = 'automation/code-scanning-ledger';
const ledgerPath = 'ledger.json';
const markerPattern = /<!-- code-scanning-alert:(\d+) analysis:([a-f0-9]{40}) -->/i;
const maxAlertAttempts = 2;

export function alertKey(alert) {
  return `${alert.number}@${alert.most_recent_instance?.commit_sha ?? ''}`;
}

function retryResult(expected, evidence) {
  return { status: 'retry', alert_number: expected.number, analysis_sha: expected.analysis_sha, evidence };
}

export function selectAlert(alerts, ledger, openPRs) {
  const activeAlerts = new Set(openPRs.map((pr) => {
    const marker = pr.body?.match(markerPattern);
    return marker ? Number(marker[1]) : 0;
  }).filter(Boolean));
  return alerts.find((alert) => {
    const key = alertKey(alert);
    const record = ledger.alerts?.[key];
    const retryable = record && ['processing', 'retrying'].includes(record.status) && (record.attempts ?? 0) < maxAlertAttempts;
    return key.endsWith('@') === false && !activeAlerts.has(alert.number) && (!record || retryable);
  });
}

export function normalizeResult(raw, expected) {
  let result;
  try {
    result = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return retryResult(expected, 'Pullfrog result was not valid JSON.');
  }
  if (!result || !['vulnerability', 'false_positive', 'blocked', 'retry'].includes(result.status)) {
    return retryResult(expected, 'Pullfrog result did not contain a supported status.');
  }
  if (typeof result.evidence !== 'string' || result.evidence.trim() === '') {
    return retryResult(expected, 'Pullfrog result did not include evidence.');
  }
  if (result.alert_number !== expected.number || result.analysis_sha !== expected.analysis_sha) {
    return retryResult(expected, 'Pullfrog result did not match the selected alert and analysis.');
  }
  if (result.status === 'vulnerability' && (!Number.isInteger(result.pull_request) || result.pull_request < 1)) {
    return retryResult(expected, 'Vulnerability result did not include a pull request number.');
  }
  return result;
}

export function analysisMatchesPullRequest(analyzedSha, headSha, mergeSha) {
  return Boolean(analyzedSha && (analyzedSha === headSha || analyzedSha === mergeSha));
}

function instanceContextKey(instance) {
  return JSON.stringify([instance.analysis_key ?? '', instance.environment ?? '', instance.category ?? '']);
}

export function evaluatePullRequest({ checkRuns, statuses = {}, mainInstances = [], prInstances = [], prRef, headSha, mergeSha }) {
  const latestChecks = new Map();
  for (const check of checkRuns) {
    const key = `${check.app?.id ?? 'unknown'}:${check.name}`;
    const previous = latestChecks.get(key);
    if (!previous || (check.id ?? 0) > (previous.id ?? 0)) latestChecks.set(key, check);
  }
  const checks = [...latestChecks.values()];
  const latestStatuses = new Map();
  for (const status of statuses.statuses ?? []) {
    const previous = latestStatuses.get(status.context);
    if (!previous || (status.id ?? 0) > (previous.id ?? 0)) latestStatuses.set(status.context, status);
  }
  const commitStatuses = [...latestStatuses.values()];
  const statusFailure = commitStatuses.some((status) => ['failure', 'error'].includes(status.state));
  const ciFailed = checks.some((check) => ['failure', 'cancelled', 'timed_out', 'action_required', 'stale', 'startup_failure'].includes(check.conclusion)) || statusFailure;
  const testRuns = checks.filter((check) => check.name === 'test').sort((left, right) => (right.id ?? 0) - (left.id ?? 0));
  const testRun = testRuns[0];
  const pendingCommitStatus = (statuses.total_count ?? 0) > 0 && (statuses.state === 'pending' || commitStatuses.some((status) => status.state === 'pending'));
  const ciPending = !testRun || testRun.status !== 'completed' || checks.some((check) => check.status !== 'completed') || pendingCommitStatus;
  const statusesPassed = (statuses.total_count ?? 0) === 0 || (statuses.state === 'success' && commitStatuses.every((status) => status.state === 'success'));
  const ciPassed = !ciPending && !ciFailed && statusesPassed && testRun.conclusion === 'success';
  const mainOpenInstances = mainInstances.filter((instance) => instance.ref === 'refs/heads/main' && instance.state === 'open');
  const requiredContexts = new Set(mainOpenInstances.map(instanceContextKey));
  const currentPRInstances = prInstances.filter((instance) => instance.ref === prRef && analysisMatchesPullRequest(instance.commit_sha, headSha, mergeSha));
  const currentByContext = new Map();
  for (const instance of currentPRInstances) {
    const key = instanceContextKey(instance);
    const instances = currentByContext.get(key) ?? [];
    instances.push(instance);
    currentByContext.set(key, instances);
  }
  const instanceCurrent = requiredContexts.size > 0 && [...requiredContexts].every((key) => currentByContext.has(key));
  const hasCurrentOpenInstance = currentPRInstances.some((instance) => instance.state === 'open');
  const contextsFixed = requiredContexts.size > 0 && [...requiredContexts].every((key) => {
    const instances = currentByContext.get(key) ?? [];
    return instances.length > 0 && instances.every((instance) => instance.state === 'fixed');
  });
  if (ciFailed) return { disposition: 'repair', reason: 'ci_failure', instanceCurrent, ciPassed: false };
  if (hasCurrentOpenInstance) return { disposition: 'repair', reason: 'alert_open', instanceCurrent, ciPassed };
  if (contextsFixed && ciPassed) return { disposition: 'verified', reason: 'ci_and_codeql_pass', instanceCurrent, ciPassed };
  return { disposition: 'pending', reason: 'checks_or_current_analysis_missing', instanceCurrent, ciPassed };
}

export function canRetryAlert(attempt) {
  return attempt < maxAlertAttempts;
}

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function context() {
  const [owner, repo] = required('GITHUB_REPOSITORY').split('/');
  return { owner, repo, token: required('GH_TOKEN'), server: process.env.GITHUB_API_URL || 'https://api.github.com' };
}

async function request(ctx, path, options = {}) {
  const response = await fetch(`${ctx.server}${path}`, {
    ...options,
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${ctx.token}`,
      'x-github-api-version': apiVersion,
      ...(options.body ? { 'content-type': 'application/json' } : {}),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`GitHub API ${options.method ?? 'GET'} ${path}: ${response.status} ${detail}`);
  }
  if (response.status === 204) return undefined;
  return response.json();
}

async function listPages(ctx, path) {
  const items = [];
  for (let page = 1; ; page += 1) {
    const batch = await request(ctx, `${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    if (!Array.isArray(batch)) throw new Error(`Expected a list from ${path}`);
    items.push(...batch);
    if (batch.length < 100) return items;
  }
}

async function listCheckRuns(ctx, sha) {
  const runs = [];
  for (let page = 1; ; page += 1) {
    const result = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/commits/${sha}/check-runs?per_page=100&page=${page}`);
    if (!Array.isArray(result.check_runs)) throw new Error('Expected check_runs in the Check Runs API response.');
    runs.push(...result.check_runs);
    if (result.check_runs.length < 100) return runs;
  }
}

async function getLedger(ctx) {
  try {
    const file = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/contents/${ledgerPath}?ref=${encodeURIComponent(ledgerBranch)}`);
    return { ledger: JSON.parse(Buffer.from(file.content, 'base64').toString('utf8')), sha: file.sha };
  } catch (error) {
    if (!String(error.message).includes('404')) throw error;
    return { ledger: { version: 1, alerts: {}, updated_at: null }, sha: null };
  }
}

async function writeLedger(ctx, ledger, sha) {
  if (!sha) {
    try {
      const mainRef = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/git/ref/heads/main`);
      await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/git/refs`, {
        method: 'POST',
        body: JSON.stringify({ ref: `refs/heads/${ledgerBranch}`, sha: mainRef.object.sha }),
      });
    } catch (error) {
      if (!String(error.message).includes('422')) throw error;
    }
  }
  const current = sha ? { sha } : await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/contents/${ledgerPath}?ref=${encodeURIComponent(ledgerBranch)}`).catch(() => null);
  await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/contents/${ledgerPath}`, {
    method: 'PUT',
    body: JSON.stringify({
      message: 'chore: code scanning alert ledgerを更新',
      content: Buffer.from(`${JSON.stringify(ledger, null, 2)}\n`).toString('base64'),
      branch: ledgerBranch,
      ...(current?.sha ? { sha: current.sha } : {}),
    }),
  });
}

async function getOpenAlerts(ctx, ref = 'refs/heads/main') {
  return listPages(ctx, `/repos/${ctx.owner}/${ctx.repo}/code-scanning/alerts?state=open&ref=${encodeURIComponent(ref)}`);
}

async function getAlertInstances(ctx, alertNumber, ref) {
  const instances = await listPages(ctx, `/repos/${ctx.owner}/${ctx.repo}/code-scanning/alerts/${alertNumber}/instances?ref=${encodeURIComponent(ref)}`);
  return instances.filter((instance) => instance.ref === ref);
}

function setOutput(name, value) {
  const path = process.env.GITHUB_OUTPUT;
  if (path) return appendFile(path, `${name}=${value}\n`);
}

function markdownCell(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

async function writeSummary(ledger, current = null) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const rows = Object.entries(ledger.alerts ?? {}).map(([key, entry]) => `| ${markdownCell(key)} | ${markdownCell(entry.status)} | ${markdownCell(entry.evidence)} |`);
  await appendFile(path, `## Code scanning agent loop\n\n${current ? `対象: alert #${current.number} / ${current.analysis_sha}\n\n` : ''}| Alert @ analysis SHA | 状態 | 根拠・結果 |\n| --- | --- | --- |\n${rows.join('\n') || '| なし | - | - |'}\n`);
}

async function writePrompt(alert, analysisSha, promptPath, mode = 'scan') {
  const message = alert.most_recent_instance?.message?.text ?? '';
  const location = alert.most_recent_instance?.location ?? {};
  const prNumber = mode === 'followup' ? Number(process.env.PR_NUMBER) : null;
  const text = mode === 'scan'
    ? `このリポジトリの CodeQL alert を1件だけ調査してください。\n\nAlert: #${alert.number}\nAnalysis commit SHA: ${analysisSha}\nRule: ${alert.rule?.id ?? ''} (${alert.rule?.severity ?? 'unknown'})\nLocation: ${location.path ?? ''}:${location.start_line ?? ''}\nMessage: ${message}\nGitHub alert: ${alert.html_url ?? ''}\n\n必ずコードと既存テストで到達可能性を調べてください。実際の脆弱性なら、共通の責任境界に最小修正と回帰テストを加え、branch security/code-scanning/alert-${alert.number}-${analysisSha} から main 向け draft PR を1件作成してください。PR本文に次の機械可読マーカーをそのまま含めてください: <!-- code-scanning-alert:${alert.number} analysis:${analysisSha} -->。CI と CodeQL に必要な説明をPR本文へ書いてください。false positive は具体的なコード上の証拠を示し、alertをdismissしないでください。証拠が足りない場合は blocked として不足点を書いてください。mainへpush・merge・alert dismissはしないでください。\n\n結果は次のJSON schemaに合う形で返してください。`
    : `Code scanning alert #${alert.number} を扱う既存 draft PR #${prNumber} のCI/CodeQL結果を確認してください。現在のPR head SHAは ${process.env.PR_HEAD_SHA} です。alert分析SHAは ${analysisSha} です。\n\nこの同じPR branchだけを修正してください。CI失敗または同じalertが現在のPR head分析で残る場合だけ、最小修正と回帰テストを追加して同じPRへpushしてください。無関係な変更や新しいPRを作らないでください。false positiveの判断やalertのdismissはしないでください。証拠が不足する場合はblockedにしてください。\n\nCI/CodeQL結果: ${message}\n\nPR: ${process.env.PR_URL}\n\nJSON schemaに合う結果を返してください。`;
  await writeFile(promptPath, `${text}\n\n{\n  "status": "vulnerability | false_positive | blocked | retry",\n  "alert_number": ${alert.number},\n  "analysis_sha": "${analysisSha}",\n  "evidence": "string",\n  "pull_request": "integer when status is vulnerability"\n}\n`);
}

async function prepare() {
  const ctx = context();
  let loaded = await getLedger(ctx);
  const { ledger } = loaded;
  const alerts = await getOpenAlerts(ctx);
  const pulls = await listPages(ctx, `/repos/${ctx.owner}/${ctx.repo}/pulls?state=open&base=main`);
  const mode = process.env.REQUESTED_MODE || 'scan';
  const requestedPR = Number(process.env.PR_NUMBER || '0');
  let changed = false;
  const openPullNumbers = new Set(pulls.map((pr) => pr.number));
  const pendingEntries = Object.entries(ledger.alerts ?? {}).filter(([, entry]) =>
    ['pending_pr', 'followup_retrying', 'processing_followup'].includes(entry.status) && entry.pull_request && !openPullNumbers.has(entry.pull_request));
  for (const [key, entry] of pendingEntries) {
    const pr = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/pulls/${entry.pull_request}`);
    if (pr.state !== 'closed') continue;
    const merged = Boolean(pr.merged || pr.merged_at);
    ledger.alerts[key] = {
      ...entry,
      status: merged ? 'merged' : 'blocked',
      evidence: merged ? `PR #${pr.number} was merged outside the agent loop.` : `PR #${pr.number} was closed without merging; the human closure was respected and the alert was not recreated.`,
      updated_at: new Date().toISOString(),
    };
    changed = true;
  }
  const pendingPulls = mode === 'followup' ? pulls.filter((pr) => pr.number === requestedPR) : pulls;
  for (const pr of pendingPulls) {
    const marker = pr.body?.match(markerPattern);
    if (!marker || !pr.draft || pr.base?.ref !== 'main' || pr.head?.repo?.full_name !== `${ctx.owner}/${ctx.repo}` || !pr.head?.ref?.startsWith('security/code-scanning/alert-')) continue;
    const key = `${marker[1]}@${marker[2]}`;
    const entry = ledger.alerts[key];
    const interruptedScan = entry && ['processing', 'retrying'].includes(entry.status) && !entry.pull_request;
    if (interruptedScan) {
      entry.status = 'pending_pr';
      entry.pull_request = pr.number;
      entry.branch = pr.head.ref;
      entry.head_sha = pr.head.sha;
      entry.evidence = 'Recovered a validated alert PR after the agent result was interrupted.';
      entry.updated_at = new Date().toISOString();
      changed = true;
    }
    if (!entry || !['pending_pr', 'followup_retrying', 'processing_followup'].includes(entry.status) || entry.pull_request !== pr.number) continue;
    const sameReservation = entry.status === 'processing_followup' && entry.followup_sha === pr.head.sha;
    const alreadyHandled = entry.last_followup_sha === pr.head.sha && entry.status !== 'followup_retrying' && !sameReservation;
    if (alreadyHandled) continue;
    const checkRuns = await listCheckRuns(ctx, pr.head.sha);
    const statuses = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/commits/${pr.head.sha}/status`);
    const prRef = `refs/pull/${pr.number}/merge`;
    const [mainInstances, prInstances] = await Promise.all([
      getAlertInstances(ctx, Number(marker[1]), 'refs/heads/main'),
      getAlertInstances(ctx, Number(marker[1]), prRef),
    ]);
    const evaluation = evaluatePullRequest({ checkRuns, statuses, mainInstances, prInstances, prRef, headSha: pr.head.sha, mergeSha: pr.merge_commit_sha });
    const currentPRInstances = prInstances.filter((item) => analysisMatchesPullRequest(item.commit_sha, pr.head.sha, pr.merge_commit_sha));
    const instance = currentPRInstances.find((item) => item.state === 'open') ?? currentPRInstances[0] ?? null;
    if (evaluation.disposition === 'verified') {
      ledger.alerts[key] = { ...entry, status: 'verified', analyzed_sha: instance.commit_sha, verified_head_sha: pr.head.sha, updated_at: new Date().toISOString() };
      changed = true;
      continue;
    }
    if (evaluation.disposition === 'pending') {
      if (sameReservation && (entry.attempts ?? 0) >= maxAlertAttempts) {
        ledger.alerts[key] = { ...entry, status: 'pending_pr', evidence: 'The reserved follow-up ended before current checks were available; the PR remains under scheduled evaluation.', updated_at: new Date().toISOString() };
        changed = true;
      }
      continue;
    }
    const attempts = (entry.attempts ?? 0) + 1;
    if (attempts > maxAlertAttempts) {
      ledger.alerts[key] = { ...entry, status: 'blocked', evidence: `CI or CodeQL still fails after the follow-up limit on ${pr.head.sha}.`, updated_at: new Date().toISOString() };
      changed = true;
      continue;
    }
    const expected = { number: Number(marker[1]), analysis_sha: marker[2] };
    const promptPath = `${process.env.RUNNER_TEMP ?? '/tmp'}/code-scanning-followup-${pr.number}.md`;
    const alert = { number: expected.number, rule: {}, most_recent_instance: { message: { text: `Follow-up reason: ${evaluation.reason}. PR instance state: ${instance?.state ?? 'analysis not available'}. CI test: ${checkRuns.find((check) => check.name === 'test')?.conclusion ?? 'not available'}. Current PR head: ${pr.head.sha}.` }, location: instance?.location ?? {} } };
    process.env.PR_HEAD_SHA = pr.head.sha;
    process.env.PR_URL = pr.html_url;
    process.env.PR_NUMBER = String(pr.number);
    await writePrompt(alert, expected.analysis_sha, promptPath, 'followup');
    ledger.alerts[key] = { ...entry, status: 'processing_followup', followup_sha: pr.head.sha, attempts, updated_at: new Date().toISOString() };
    ledger.updated_at = new Date().toISOString();
    await writeLedger(ctx, ledger, loaded.sha);
    await setOutput('has_work', 'true');
    await setOutput('task_mode', 'followup');
    await setOutput('prompt_b64', Buffer.from(await readFile(promptPath)).toString('base64'));
    await setOutput('expected', Buffer.from(JSON.stringify(expected)).toString('base64'));
    await setOutput('pr_number', String(pr.number));
    await setOutput('pr_head_sha', pr.head.sha);
    await setOutput('followup_attempt', String(attempts));
    await writeSummary(ledger, expected);
    return;
  }
  if (mode === 'followup') {
    if (changed) {
      ledger.updated_at = new Date().toISOString();
      await writeLedger(ctx, ledger, loaded.sha);
    }
    await writeSummary(ledger);
    await setOutput('has_work', 'false');
    return;
  }
  for (const alert of alerts) {
    const key = alertKey(alert);
    const record = ledger.alerts[key];
    if (record && ['processing', 'retrying'].includes(record.status) && (record.attempts ?? 0) >= maxAlertAttempts) {
      ledger.alerts[key] = { ...record, status: 'blocked', evidence: 'Agent attempt limit reached after an interrupted run or retry.', updated_at: new Date().toISOString() };
      changed = true;
    }
  }
  const target = selectAlert(alerts, ledger, pulls);
  if (!target) {
    if (changed) {
      ledger.updated_at = new Date().toISOString();
      await writeLedger(ctx, ledger, loaded.sha);
    }
    await writeSummary(ledger);
    await setOutput('has_work', 'false');
    return;
  }
  const analysisSha = target.most_recent_instance?.commit_sha;
  const key = `${target.number}@${analysisSha}`;
  const attempt = (ledger.alerts[key]?.attempts ?? 0) + 1;
  const item = { number: target.number, analysis_sha: analysisSha, attempt };
  ledger.alerts[key] = { status: 'processing', attempts: attempt, evidence: 'Agent attempt reserved before execution.', updated_at: new Date().toISOString() };
  ledger.updated_at = new Date().toISOString();
  await writeLedger(ctx, ledger, loaded.sha);
  const promptPath = `${process.env.RUNNER_TEMP ?? '/tmp'}/code-scanning-alert-${target.number}.md`;
  await writePrompt(target, analysisSha, promptPath);
  await setOutput('has_work', 'true');
  await setOutput('task_mode', 'scan');
  await setOutput('alert_number', String(item.number));
  await setOutput('analysis_sha', analysisSha);
  await setOutput('prompt_b64', Buffer.from(await readFile(promptPath)).toString('base64'));
  await setOutput('expected', Buffer.from(JSON.stringify(item)).toString('base64'));
  await writeSummary(ledger, item);
}

async function verifyPullRequest(ctx, result, expected) {
  const pr = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/pulls/${result.pull_request}`);
  const marker = pr.body?.match(markerPattern);
  if (pr.state !== 'open' || !pr.draft || pr.base?.ref !== 'main' || pr.head?.repo?.full_name !== `${ctx.owner}/${ctx.repo}` || !pr.head?.ref?.startsWith('security/code-scanning/alert-')) {
    throw new Error('Pullfrog PR is not an open security branch targeting main.');
  }
  if (!marker || Number(marker[1]) !== expected.number || marker[2] !== expected.analysis_sha) {
    throw new Error('Pullfrog PR body does not identify the selected alert analysis.');
  }
  return pr;
}

async function dispatchNext(ctx) {
  await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/actions/workflows/code-scanning-agent-loop.yml/dispatches`, {
    method: 'POST',
    body: JSON.stringify({ ref: 'main', inputs: { mode: 'scan' } }),
  });
}

async function finalize() {
  if (process.env.TASK_MODE === 'followup') return finalizeFollowup();
  const ctx = context();
  const expected = JSON.parse(Buffer.from(required('EXPECTED_ALERT'), 'base64').toString('utf8'));
  const { ledger, sha } = await getLedger(ctx);
  const raw = process.env.AGENT_RESULT_B64 ? Buffer.from(process.env.AGENT_RESULT_B64, 'base64').toString('utf8') : '';
  const result = normalizeResult(raw, expected);
  const attempt = expected.attempt;
  let entry;
  if (result.status === 'retry' && canRetryAlert(attempt)) {
    ledger.alerts[`${expected.number}@${expected.analysis_sha}`] = { status: 'retrying', attempts: attempt, evidence: result.evidence, updated_at: new Date().toISOString() };
    ledger.updated_at = new Date().toISOString();
    await writeLedger(ctx, ledger, sha);
    await setOutput('retry', 'true');
    await setOutput('summary', result.evidence);
    await dispatchNext(ctx);
    return;
  }
  if (result.status === 'retry') {
    const pulls = await listPages(ctx, `/repos/${ctx.owner}/${ctx.repo}/pulls?state=open&base=main`);
    const pr = pulls.find((candidate) => {
      const marker = candidate.body?.match(markerPattern);
      return marker && Number(marker[1]) === expected.number && marker[2] === expected.analysis_sha;
    });
    if (pr) {
      try {
        const validatedPR = await verifyPullRequest(ctx, { ...result, pull_request: pr.number }, expected);
        entry = { status: 'pending_pr', attempts: attempt, evidence: 'Recovered a validated alert PR after the final agent result was unavailable.', pull_request: validatedPR.number, branch: validatedPR.head.ref, head_sha: validatedPR.head.sha, updated_at: new Date().toISOString() };
      } catch (error) {
        entry = { status: 'blocked', attempts: attempt, evidence: `PR recovery validation failed: ${error.message}`, updated_at: new Date().toISOString() };
      }
    }
  }
  if (result.status === 'retry' && !entry) result.status = 'blocked';
  if (!entry && result.status === 'vulnerability') {
    try {
      const pr = await verifyPullRequest(ctx, result, expected);
      entry = { status: 'pending_pr', attempts: expected.attempt, evidence: result.evidence, pull_request: pr.number, branch: pr.head.ref, head_sha: pr.head.sha, updated_at: new Date().toISOString() };
    } catch (error) {
      entry = { status: 'blocked', evidence: `PR validation failed: ${error.message}`, updated_at: new Date().toISOString() };
    }
  } else if (!entry) {
    entry = { status: result.status, attempts: expected.attempt, evidence: result.evidence, updated_at: new Date().toISOString() };
  }
  ledger.alerts[`${expected.number}@${expected.analysis_sha}`] = entry;
  ledger.updated_at = new Date().toISOString();
  await writeLedger(ctx, ledger, sha);
  await writeSummary(ledger, expected);
  await dispatchNext(ctx);
  await setOutput('retry', 'false');
  await setOutput('summary', entry.status);
}

async function finalizeFollowup() {
  const ctx = context();
  const expected = JSON.parse(Buffer.from(required('EXPECTED_ALERT'), 'base64').toString('utf8'));
  const prNumber = Number(required('PR_NUMBER'));
  const { ledger, sha } = await getLedger(ctx);
  const key = `${expected.number}@${expected.analysis_sha}`;
  const entry = ledger.alerts[key];
  if (!entry || entry.pull_request !== prNumber) throw new Error('Follow-up does not match a pending alert PR.');
  const raw = process.env.AGENT_RESULT_B64 ? Buffer.from(process.env.AGENT_RESULT_B64, 'base64').toString('utf8') : '';
  const result = normalizeResult(raw, expected);
  const pr = await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/pulls/${prNumber}`);
  const attempt = Number(process.env.FOLLOWUP_ATTEMPT ?? '1');
  entry.last_followup_result = result.status;
  entry.attempts = attempt;
  entry.last_followup_sha = process.env.PR_HEAD_SHA;
  entry.updated_at = new Date().toISOString();
  if (result.status === 'vulnerability' && result.pull_request !== prNumber) {
    result.status = 'blocked';
    result.evidence = 'Follow-up result referenced a different pull request.';
  }
  const pushedCommit = pr.head.sha !== process.env.PR_HEAD_SHA;
  if (pushedCommit && result.status !== 'vulnerability') {
    entry.status = 'pending_pr';
    entry.head_sha = pr.head.sha;
    entry.evidence = `Agent result was ${result.status}, but PR head advanced to ${pr.head.sha}; CI and CodeQL will be evaluated independently.`;
    ledger.alerts[key] = entry;
    ledger.updated_at = new Date().toISOString();
    await writeLedger(ctx, ledger, sha);
    await writeSummary(ledger, expected);
    await dispatchNext(ctx);
    return;
  }
  if (result.status === 'retry' && canRetryAlert(attempt)) {
    entry.status = 'followup_retrying';
    entry.followup_sha = process.env.PR_HEAD_SHA;
    entry.evidence = result.evidence;
    ledger.alerts[key] = entry;
    ledger.updated_at = new Date().toISOString();
    await writeLedger(ctx, ledger, sha);
    await request(ctx, `/repos/${ctx.owner}/${ctx.repo}/actions/workflows/code-scanning-agent-loop.yml/dispatches`, {
      method: 'POST',
      body: JSON.stringify({ ref: 'main', inputs: { mode: 'followup', pr_number: String(prNumber) } }),
    });
    return;
  }
  if (result.status !== 'vulnerability' || !pushedCommit) {
    entry.status = 'blocked';
    entry.evidence = result.evidence || `Agent did not push a new commit to PR #${prNumber}.`;
  } else {
    entry.status = 'pending_pr';
    entry.head_sha = pr.head.sha;
    entry.evidence = result.evidence;
  }
  ledger.alerts[key] = entry;
  ledger.updated_at = new Date().toISOString();
  await writeLedger(ctx, ledger, sha);
  await writeSummary(ledger, expected);
  await dispatchNext(ctx);
}

async function normalizeStep() {
  const expected = JSON.parse(Buffer.from(required('EXPECTED_ALERT'), 'base64').toString('utf8'));
  const raw = process.env.AGENT_RESULT ?? '';
  const result = normalizeResult(raw, expected);
  const attempt = Number(process.env.ATTEMPT ?? '1');
  const retry = result.status === 'retry' && canRetryAlert(attempt);
  await setOutput('retry', retry ? 'true' : 'false');
  await setOutput('result_b64', Buffer.from(JSON.stringify(result)).toString('base64'));
  await setOutput('status', result.status);
}

async function decodePrompt() {
  const path = '.git/code-scanning-agent-prompt.md';
  await writeFile(path, Buffer.from(required('PROMPT_B64'), 'base64'));
  await setOutput('path', path);
}

async function cleanupPrompt() {
  await import('node:fs/promises').then(({ unlink }) => unlink('.git/code-scanning-agent-prompt.md').catch(() => {}));
}

export async function main(command = process.argv[2]) {
  if (command === 'prepare') return prepare();
  if (command === 'finalize') return finalize();
  if (command === 'finalize-followup') return finalizeFollowup();
  if (command === 'normalize') return normalizeStep();
  if (command === 'decode-prompt') return decodePrompt();
  if (command === 'cleanup-prompt') return cleanupPrompt();
  throw new Error(`Unknown command: ${command}`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
