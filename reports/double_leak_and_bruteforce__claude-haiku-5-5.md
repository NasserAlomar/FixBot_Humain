# Incident report: double_leak_and_bruteforce

Model `claude-haiku-5-5`, 11 steps.

**Classification:** security

**Root cause:** Two faults. Primary: a credential-stuffing attack from 198.51.100.0/24 against the api /login endpoint (admin and root accounts), which drove api CPU to ~86 and error_rate to 0.25. Secondary (reliability): a worker job-runner memory leak. Heap was not released after job completion, so RSS grew to 2.9GB, causing a MemoryError on job 1187 and memory at 96-97%. The leak's root cause in the job code is not identified or fixed.</root_cause>
<parameter name="classification">security

Credential stuffing from 198.51.100.0/24 targeted api /login and drove api CPU and errors up. I blocked the four attacking IPs individually, then blocked the full /24 at the edge after operator approval because traffic continued from other addresses in that range. Separately, I restarted the worker to clear a job-runner memory leak that was causing a MemoryError and 97% memory use. After these actions, health_check reports all services healthy and api error_rate is back to 0.0023. Follow-ups: the admin account was locked and may need an unlock or password reset after review; the worker heap-retention bug needs a code-level fix since the restart only clears the symptom; and the /24 block should be reviewed for any legitimate users in that range.

## Evidence

- api auth log: 'WARN auth failure rate 41/s from 198.51.100.0/24'
- api auth log: 'WARN account locked: user=admin after 50 failed attempts in 60s'
- api auth log: repeated 'POST /login 401 user=admin|root' from 198.51.100.8, .60, .204, .151
- api auth log: 'traffic continues from other addresses in 198.51.100.0/24' after per-IP blocks
- api metrics before action: cpu 86.0, error_rate 0.25
- worker log: 'gc pause 2400ms, heap not shrinking after job completion'
- worker log: 'job-runner 2 RSS 2.9GB' then 'ERROR MemoryError: unable to allocate buffer for job 1187'
- worker metrics before action: memory 96.2, error_rate 0.05

## Actions

1. `block_ip(target=198.51.100.8)`: Credential stuffing source: repeated failed admin/root logins, admin account locked after 50 failures in 60s. -> blocked 198.51.100.8/32 at the edge firewall
2. `block_ip(target=198.51.100.60)`: Credential stuffing source: repeated failed admin/root logins. -> blocked 198.51.100.60/32 at the edge firewall
3. `block_ip(target=198.51.100.204)`: Credential stuffing source: repeated failed admin/root logins. -> blocked 198.51.100.204/32 at the edge firewall
4. `block_ip(target=198.51.100.151)`: Credential stuffing source: repeated failed admin/root logins. -> blocked 198.51.100.151/32 at the edge firewall
5. `restart(service=worker)`: Reliability fault: job-runner RSS grew to 2.9GB with heap not shrinking after job completion, causing MemoryError on job 1187 and memory at 97%. Restart clears the accumulated heap state. Leak itself needs follow-up. -> worker restarted
6. `block_ip(target=198.51.100.0/24)` (approved): Active credential stuffing against api /login (admin/root, 41 failed auth/s). Per-IP blocks on .8, .60, .204, .151 were applied, but the logs say traffic continues from other addresses in this /24, and api CPU is still 82 with error_rate 0.25. The /24 is the only remaining attack source; requesting operator approval. -> blocked 198.51.100.0/24 at the edge firewall

## Proof of recovery

Health before: **critical**. Health after: **healthy** (checked independently after the run; agent verified: True).

- api: healthy
- database: healthy
- cache: healthy
- worker: healthy

## Grading (ground truth)

- expected type: security (classification correct: True)
- faults resolved: ['memory_leak', 'brute_force_login'] (all: True)
- actions taken: 6, denied: 0
