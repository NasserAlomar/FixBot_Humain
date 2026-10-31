# Incident report: crypto_miner

Model `claude-haiku-5-5`, 5 steps.

**Classification:** security

**Root cause:** An unauthorized cryptominer process, kworker-upd (pid 4412), was running on the worker host. It was spawned from cron and used about 380% CPU. It also maintained an outbound connection to pool.miner.example.test:4444, a mining-pool endpoint. The CPU exhaustion starved the job runners, which caused the 80% throughput drop and the elevated error rate.

The worker was flagged critical with CPU at 99% and a 3% error rate. Logs showed the kworker-upd process, which was spawned from cron and was mining cryptocurrency while connected to a mining pool. I classified the incident as security and killed the process. I did not restart anything or change config. Health check now reports all services healthy, and worker CPU is at 35% with error rate 0.17%. Follow-up: confirm the quarantined cron entry is removed and find how the cron entry was created, since the worker auth/config logs were empty.

## Evidence

- [t=0003] WARN process kworker-upd (pid 4412) using 380% cpu, parent=cron
- [t=0003] WARN outbound connection to pool.miner.example.test:4444 from kworker-upd
- [t=0003] INFO job throughput dropped 80% since 02:13
- health_check before action: worker critical, cpu 99.0, error_rate 0.03
- After kill_process: health_check overall healthy; worker cpu 35.2, error_rate 0.0017; process list shows only worker: main, job-runner 1, job-runner 2
- [t=0003] INFO kworker-upd killed, cron entry quarantined

## Actions

1. `kill_process(service=worker, process=kworker-upd)`: Unauthorized cryptominer process (pid 4412, 380% CPU, spawned from cron) connecting to pool.miner.example.test:4444. Killing it removes the CPU exhaustion and the outbound mining traffic. -> killed kworker-upd on worker

## Proof of recovery

Health before: **critical**. Health after: **healthy** (checked independently after the run; agent verified: True).

- api: healthy
- database: healthy
- cache: healthy
- worker: healthy

## Grading (ground truth)

- expected type: security (classification correct: True)
- faults resolved: ['crypto_miner'] (all: True)
- actions taken: 1, denied: 0
