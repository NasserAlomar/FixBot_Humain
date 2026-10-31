# Incident report: brute_force_login

Model `claude-sonnet-5-5`, 5 steps.

**Classification:** security

**Root cause:** Distributed brute-force/credential-stuffing attack on the api /login endpoint from 198.51.100.0/24, which drove api CPU and error rate high.

The api was degraded by a login brute-force attack from 198.51.100.0/24. I classified it as security and blocked that /24 at the edge firewall. The block was approved. After that, health_check reported all services healthy. No secrets looked compromised (the admin account locked after 50 failed attempts), but I recommend reviewing admin credentials and adding login rate limiting.

## Evidence

- POST /login 401 user=admin/root from 198.51.100.93, .76, .182, .69
- WARN account locked: user=admin after 50 failed attempts in 60s
- WARN auth failure rate 41/s from 198.51.100.0/24
- api cpu 86%, error_rate 0.25 before fix; other services healthy

## Actions

1. `block_ip(target=198.51.100.0/24)` (approved): Brute-force login attack (41 failures/s on admin/root) from several IPs all in this /24; all observed traffic from it is malicious, blocking stops CPU load and errors. -> blocked 198.51.100.0/24 at the edge firewall

## Proof of recovery

Health before: **critical**. Health after: **healthy** (checked independently after the run; agent verified: True).

- api: healthy
- database: healthy
- cache: healthy
- worker: healthy

## Grading (ground truth)

- expected type: security (classification correct: True)
- faults resolved: ['brute_force_login'] (all: True)
- actions taken: 1, denied: 0
