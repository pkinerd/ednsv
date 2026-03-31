# Poll Build Logs

## Instructions

After pushing code changes, use this process to monitor for CI build results and analyze them when available.

Build logs are stored as folders on a single `build-logs` orphan branch. Each folder is named `<run_number>-<run_id>-<timestamp>-<status>` and contains:
- `build-summary.md` — build metadata (run number, commit, branch, PR, result)
- `jobs.json` — full GitHub Actions jobs API response (includes `head_sha`)
- `*.log` — individual job logs (e.g. `build-&-test.log`, `docker-build-&-push.log`)
- `test-reports/` — test output artifacts from the CI run

**IMPORTANT — Always poll when explicitly invoked:** When this skill is invoked explicitly by the user, always assume a build is expected (e.g., a PR may have been created, a merge may be in progress, or CI may have been triggered externally). Do NOT try to infer CI trigger rules from the workflow configuration or refuse to poll because you believe no build will be triggered. If no matching build exists yet for the current HEAD commit, proceed to the polling loop (Step 3).

The only case where you should skip the polling loop is when a matching build already exists (Step 2) — i.e., a build that matches both the current branch and HEAD commit SHA has already completed.

### Blobless Fetch Helper

To avoid downloading all build log content (~300-500KB per build, ~3-5MB total), use blobless fetches throughout. The `-c` overrides prevent permanent config changes to the user's repo:

```bash
# Blobless fetch — downloads only tree/commit objects, not file content
git -c remote.origin.promisor=true \
    -c remote.origin.partialclonefilter=blob:none \
    fetch origin build-logs --depth=1 --filter=blob:none

# Read a specific file — triggers on-demand fetch of just that one blob
git -c remote.origin.promisor=true \
    -c remote.origin.partialclonefilter=blob:none \
    show origin/build-logs:<folder>/<file>
```

Use these patterns for ALL git fetch and git show operations in this skill.

### Step 1: Identify the Branch and Commit

Note the current branch name and HEAD commit SHA for matching later:

```bash
git branch --show-current
git rev-parse HEAD
```

Record both values — `BRANCH` and `HEAD_SHA`. The branch is used for initial matching, and the commit SHA is used to verify the build covers the current code (not a stale push).

### Step 2: Snapshot and Check for Existing Match

Get the current tip SHA of the `build-logs` branch and list build folders:

```bash
git ls-remote origin refs/heads/build-logs
```

Record the SHA as `LAST_SHA`. If the branch doesn't exist, there are no builds yet — proceed to polling.

Fetch the branch (blobless) and list build folders:

```bash
git -c remote.origin.promisor=true \
    -c remote.origin.partialclonefilter=blob:none \
    fetch origin build-logs --depth=1 --filter=blob:none
git ls-tree origin/build-logs --name-only | sort -t- -k1 -rn
```

Note the highest run number. **Check if the most recent build folder already matches the current branch and commit** using the verification process in Step 4. If it matches, **skip polling entirely** and proceed directly to reporting the result.

This handles the common case where CI has already completed before polling starts — for example, when resuming a session where a previous push already triggered and completed a build.

### Step 3: Wait and Check Periodically

CI builds typically take **15-30 minutes**, but builds with early errors can fail in under 5 minutes. Use a repeating check pattern with **60-second intervals for 45 cycles** (~45 minutes total):

1. **Launch ONE background task** to sleep and then check the branch tip SHA:
   ```bash
   sleep 60 && git ls-remote origin refs/heads/build-logs
   ```
   Run this with `run_in_background: true`.

2. **STOP and WAIT for the `task-notification`** that signals the background task completed. Do NOT read the output file, do NOT launch another cycle, and do NOT send any message to the user until you receive the `task-notification` for this specific task ID. The sleep takes 60 seconds — you must wait the full duration.

3. **Only after receiving the `task-notification`**, read the output file. Compare the returned SHA against `LAST_SHA`:
   - If the SHA is **unchanged**, no new build was pushed — go back to step 1.
   - If the SHA **changed**, a new build was pushed — update `LAST_SHA` and proceed to Step 4.

4. If no change yet, **go back to step 1** — launch another single background sleep+check.

5. If the SHA changed, proceed to Step 4.

6. **Give up after 45 cycles** (~45 minutes of checking). You MUST run all 45 cycles before giving up — do NOT stop early.

**CRITICAL — Polling is SYNCHRONOUS, not asynchronous:** Each poll cycle is a blocking wait. After launching one background task, you MUST completely stop and produce NO tool calls and NO text output until you receive the `task-notification` for that specific task ID in a new conversation turn. The `task-notification` arrives as a system message — you cannot trigger it yourself. The 60-second sleep means you will be idle for 60 seconds. This is expected and correct.

**Common mistake to avoid:** Do NOT treat polling as an async fire-and-forget loop. Do NOT launch a background task and then immediately read its output file or launch the next cycle. The output file will be empty because the task is still sleeping. You must wait for the `task-notification` to arrive in a subsequent conversation turn before proceeding.

**CRITICAL — One task at a time:** Launch exactly ONE background task per cycle. After launching it, you MUST wait for its `task-notification` before doing anything else related to polling. Do NOT:
- Read the output file immediately after launching (it will be empty — the task is still sleeping)
- Launch multiple background tasks in rapid succession
- Try to "check" on the task before it completes
- Use any tool calls between launching and receiving the task-notification

**CRITICAL — Run all 45 cycles:** You MUST keep polling for the full 45 cycles before giving up. Track your cycle count (e.g., "Poll cycle 7/45"). Do NOT give up early because "no changes were detected" — CI builds take 15-30 minutes, so it is normal to see no changes for many cycles.

**Why 60-second intervals:** The Claude Code web platform requires background tasks to complete within 90 seconds. A 60-second sleep+check completes well within this limit while providing frequent updates.

**Silence between polls:** Do NOT send a message to the user for each intermediate check. Only notify the user when a matching build result is found or when giving up after timeout. Between polls, continue working on other tasks if available, or remain silent.

**No duplicate polling:** Do NOT invoke this skill if polling is already in progress. Before starting, check whether there are active background poll tasks from a previous invocation. Only one polling loop should be active at a time.

### Step 4: Fetch and Analyze the Build Log

When the `build-logs` branch SHA has changed (or when checking an existing build from Step 2):

```bash
git -c remote.origin.promisor=true \
    -c remote.origin.partialclonefilter=blob:none \
    fetch origin build-logs --depth=1 --filter=blob:none
git ls-tree origin/build-logs --name-only | sort -t- -k1 -rn
```

Identify new build folders (run numbers higher than previously seen). For the most recent matching folder, read the summary:

```bash
git -c remote.origin.promisor=true \
    -c remote.origin.partialclonefilter=blob:none \
    show origin/build-logs:<folder>/build-summary.md
```

**Verify it matches** using two checks:

1. **Branch match**: Check the `Branch` or `PR` field in build-summary.md matches the current branch name.
2. **Commit match**: Extract the `head_sha` from `jobs.json` to verify the build was triggered by the current HEAD commit:
   ```bash
   git -c remote.origin.promisor=true \
       -c remote.origin.partialclonefilter=blob:none \
       show origin/build-logs:<folder>/jobs.json \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['jobs'][0]['head_sha'])"
   ```
   Compare this value against `HEAD_SHA` recorded in Step 1. The `head_sha` in `jobs.json` is the actual branch HEAD commit (not the merge commit shown in build-summary.md), so it can be compared directly with `git rev-parse HEAD`.

**Both checks must pass.** If the branch matches but the commit does not, the build is stale (from a previous push) — ignore it and continue polling for a newer build.

**If multiple new folders appeared** since your last check, pick the one with the highest run number that matches both branch and commit.

**If the new folder does not match** your branch or commit, ignore it and continue polling — another PR's build or a stale build should not terminate your poll loop.

#### On success (pass)

Report to the user that the build passed.

#### On failure (fail)

1. Fetch the log for the failing build:
   ```bash
   git -c remote.origin.promisor=true \
       -c remote.origin.partialclonefilter=blob:none \
       show origin/build-logs:<folder>/build-and-test.log | grep 'error:\|FAIL'
   ```

2. If test failures are involved, test output artifacts are available at `<folder>/test-reports/` and can be fetched the same way.

3. Analyze the failures and determine if they are related to the session's changes.

4. If failures are related, fix them, commit, push, and restart polling from Step 1.

### Step 5: Report to User

Provide a clear summary:
- **Pass**: "CI build passed for commit `<sha>` on branch `<branch>`."
- **Fail**: Include the specific errors/test failures and whether they relate to session changes.
- **Timeout**: Explain that CI hasn't completed yet and suggest next steps.

## Example Flow

### Happy path

```
User: Push my changes and let me know if the build passes.

Claude:
1. Commits and pushes to the PR branch
2. Records: BRANCH=claude/my-feature, HEAD_SHA=abc1234
3. Fetches build-logs branch, lists folders — highest run is 150, doesn't match
4. Records LAST_SHA from ls-remote
5. Launches ONE background task: sleep 60 && git ls-remote origin refs/heads/build-logs
6. STOPS and WAITS — does nothing until task-notification arrives
7. [1 min later] Receives task-notification (cycle 1/45), reads output — SHA unchanged
8. Launches another ONE background task, WAITS again
9. [repeats silently for many cycles — this is normal]
10. [~20 min later, cycle 20/45] Receives task-notification — SHA changed!
11. Fetches build-logs (blobless), lists folders — new folder: 151-...-pass
12. Reads build-summary.md (on-demand blob fetch of just that file) — Branch matches
13. Reads jobs.json head_sha — matches abc1234
14. Reports: "CI build passed for commit abc1234 on branch claude/my-feature."
```

### Non-matching build (another PR's build)

```
Claude:
1. Polling for BRANCH=claude/my-feature, highest run=150
2. [5 min later, cycle 5/45] SHA changed — fetches, sees new folder 151-...-fail
3. Reads build-summary.md, sees Branch=claude/other-pr — no match
4. Ignores it, updates LAST_SHA, launches next background task, WAITS
5. [18 min later, cycle 18/45] SHA changed again — new folder 152-...-pass
6. Reads build-summary.md, sees Branch=claude/my-feature — match!
7. Reports result to user
```

### Existing build already matches (resumed session)

```
User: [Resumes session] Poll for build logs.

Claude:
1. Records: BRANCH=claude/my-feature, HEAD_SHA=abc1234
2. Fetches build-logs branch (blobless), lists folders — highest is 177-...-pass
3. Reads build-summary.md for folder 177, sees Branch=claude/my-feature — match
4. Reads jobs.json head_sha for folder 177 — abc1234 — commit matches!
5. Skips polling entirely, reports: "CI build already passed for commit abc1234 on branch claude/my-feature (run #177)."
```

### Stale build (new commits pushed after previous build)

```
User: [Resumes session, pushes new commit] Poll for build logs.

Claude:
1. Records: BRANCH=claude/my-feature, HEAD_SHA=def5678
2. Fetches build-logs branch (blobless), lists folders — highest is 177-...-pass
3. Reads build-summary.md for folder 177, sees Branch=claude/my-feature — match
4. Reads jobs.json head_sha — abc1234 — does NOT match def5678
5. Build is stale, proceeds to polling loop for a newer build
6. [~20 min later] SHA changed — new folder 178-...-pass
7. Verifies branch AND commit match — reports result
```

## Important Notes

- `git ls-remote` only fetches ref names — very lightweight, safe to run frequently.
- Blobless fetches (`--filter=blob:none`) download only tree metadata (~KB), not log file content (~300-500KB per build). Individual files are fetched on demand via `git show` with the `-c` promisor overrides.
- Only the 50 most recent build folders are retained on the `build-logs` branch.
- The `Branch` field in build-summary.md is only present for `pull_request` events (not `push` events to dev/main).
