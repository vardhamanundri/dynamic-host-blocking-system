# Dynamic Host Blocking System

**Computer Networks Mini-Project — Project 12**

## Objective

Detect abnormal TCP connection traffic and temporarily block suspicious source hosts using SDN flow rules.

## Required deliverables

1. Generate TCP traffic from multiple hosts — `tcp_app.py` client mode.
2. Monitor connection rates — controller counts TCP SYN packets per source.
3. Collect flow statistics — controller polls packet and byte counters.
4. Define abnormal thresholds — 8 SYNs in a 5-second sliding window.
5. Detect suspicious hosts — controller flags a source that reaches the threshold.
6. Maintain a dynamic blocklist — source IP is blocked for 25 seconds.
7. Install SDN DROP rules — OpenFlow priority-200 rule blocks the source IP.

## Small architecture

- h1 (`10.0.0.1`): normal TCP client
- h2 (`10.0.0.2`): high-rate client used to trigger detection
- h3 (`10.0.0.3`): legitimate client tested during the attack
- h4 (`10.0.0.4:5001`): TCP server
- s1: Mininet Open vSwitch, controlled using OpenFlow 1.3
- `controller.py`: OS-Ken SDN controller

Mininet creates the virtual hosts and switch. Open vSwitch is the programmable switch. OS-Ken manages its flow table through OpenFlow. Eventlet is a runtime dependency of this OS-Ken setup, not a separate project feature.

## Four Python files

| File | Purpose |
|---|---|
| `controller.py` | SYN monitoring, threshold detection, blocklist, DROP rules and flow statistics |
| `topology.py` | Four-host Mininet topology |
| `tcp_app.py` | Threaded TCP server and rate-controlled traffic client |
| `performance_test.py` | Static-OVS baseline, dynamic-SDN test and CSV comparison |

## Run

Use Ubuntu/WSL with Mininet, Open vSwitch, Python 3 and OS-Ken installed. Install the Python dependencies with `pip install -r requirements.txt`, then run from this directory:

```bash
sudo mn -c
sudo python3 performance_test.py
```

The test creates the static-OVS baseline, then starts the controller and repeats the traffic test with dynamic blocking. It checks that h2 is blocked, h3 continues communicating and h2 reconnects after the cooldown.

All measured rows are written to `performance_results.csv`. Controller events are written to `controller_performance.log`.

## Detection settings

| Setting | Value |
|---|---:|
| SYN window | 5 seconds |
| Threshold | 8 SYN packets |
| Block duration | 25 seconds |
| Flow-statistics polling | 4 seconds |
| SYN monitor priority | 100 |
| DROP rule priority | 200 |

Example DROP rule:

```text
priority=200,ip,nw_src=10.0.0.2 actions=drop
```

## Viva points

- **Why TCP SYN?** SYN is used to initiate a TCP connection, so counting SYN packets estimates connection attempts.
- **What is a sliding window?** It counts only recent SYN timestamps and removes entries older than five seconds.
- **Why OpenFlow?** It lets the controller add and delete rules in the switch flow table.
- **How is a host blocked?** A higher-priority DROP rule matches its source IP.
- **How does recovery work?** After 25 seconds, the controller deletes the DROP rule and removes the IP from its blocklist.
- **Why h3?** It demonstrates that a legitimate host below the threshold can still reach the server while h2 is blocked.

## Result interpretation

`performance_results.csv` records attempts, successes, timeouts, connection refusals, success rate and successful request/response latency. Results depend on the test environment; repeat experiments for averaged benchmarks. The client uses a connection timeout, so blocked attempts take longer and total attempt counts may differ from the baseline.
