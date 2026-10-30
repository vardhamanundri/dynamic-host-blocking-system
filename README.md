# Dynamic Host Blocking System

**Computer Networks mini-project — SDN and Mininet**

## Problem

Detect hosts generating excessive TCP connection requests and dynamically block them using SDN flow rules.

## Network

Four Mininet hosts connect to one Open vSwitch (`s1`). Host `h4` runs the TCP server; `h1` and `h3` are legitimate clients; `h2` generates abnormal traffic. OS-Ken controls `s1` using OpenFlow 1.3.

| Host | Address | Role |
|---|---|---|
| h1 | 10.0.0.1 | Normal client |
| h2 | 10.0.0.2 | Suspicious client |
| h3 | 10.0.0.3 | Legitimate client |
| h4 | 10.0.0.4 | TCP server, port 5001 |

## Detection settings

- Sliding window: 5 seconds
- Threshold: 8 TCP SYN packets per source IP
- Block duration: 25 seconds
- Flow statistics interval: 4 seconds
- Flow priorities: 100 (SYN monitor), 200 (DROP)

OVS forwards ordinary traffic using its `NORMAL` action. It sends a copy of each TCP SYN (SYN set, ACK clear) to the controller. When a source reaches the threshold, OS-Ken installs a higher-priority DROP rule. The controller removes the rule after the cooldown; a 29-second switch hard timeout is a fallback if the controller stops.

## Files

- `controller.py` — SYN monitoring, threshold detection, blocklist, DROP rule, recovery and flow statistics.
- `topology.py` — Four-host, one-switch Mininet topology.
- `tcp_app.py` — Concurrent TCP server and rate-controlled client.
- `performance_test.py` — Static OVS baseline and dynamic SDN test; produces `performance_results.csv` and `controller_performance.log`.

## Requirements

Ubuntu with Mininet and Open vSwitch installed, plus Python 3 and OS-Ken. The tested environment used OS-Ken 3.1.1 and Eventlet 0.40.4. OVS is the programmable OpenFlow switch used by Mininet; Eventlet is an OS-Ken runtime dependency.

On Ubuntu, install the network tools with:

```bash
sudo apt update
sudo apt install mininet openvswitch-switch
python3 -m pip install -r requirements.txt
```

If OS-Ken was installed in a user-local Python environment, ensure `osken-manager` is on the PATH inherited by `sudo`.

## Run

From this folder:

```bash
sudo mn -c
sudo python3 performance_test.py
```

The test runs the static baseline first, then the dynamic controller experiment. It generates fresh CSV results; each run replaces the previous `performance_results.csv` and controller log. The dynamic phase checks the h2 DROP rule, verifies h3 is not blocked, waits for h2 recovery, and tests h2 again.

## Deliverables covered

1. Multiple TCP clients: `tcp_app.py` client mode on h1, h2 and h3.
2. Connection-rate monitoring: per-source SYN timestamp window in `controller.py`.
3. Flow statistics: periodic OpenFlow statistics requests and packet/byte logging.
4. Abnormal threshold: 8 SYNs within 5 seconds.
5. Suspicious-host detection: controller alert when threshold is reached.
6. Dynamic blocklist: source IP and expiry timestamp, with automatic removal.
7. SDN DROP rule: priority-200 OpenFlow rule matching the source IPv4 address.

## Notes for evaluation

The triggering SYN is copied to the controller while OVS forwards the original packet. The controller then installs the DROP rule; subsequent matching traffic is dropped. Thus the threshold-triggering connection may complete, while later attempts time out.

The baseline and dynamic experiments use the same topology and traffic rates. The client stops after a 0.4-second socket timeout, so blocked attempts take longer and the number of attempts during a fixed-duration attack is lower. Report successful attacker connections and legitimate-host success alongside rates; do not compare attempt totals as if offered loads were identical. Run repeated trials if averaged results are required.

## Experimental Results

The following results were obtained from the latest Mininet experiment.

| Test | Static OVS | Dynamic SDN |
|---|---:|---:|
| Normal h1 connections | 3/3 | 3/3 |
| Attack h2 connections | 120/120 | 8/22 |
| Legitimate h3 connections | 6/6 | 6/6 |
| h2 after recovery | N/A | 3/3 |

### Additional Measurements

| Metric | Observed Result |
|---|---:|
| SYN detection threshold | 8 SYNs in 5 seconds |
| First failed attack connection | 0.8 seconds |
| Attacker timeouts | 14 |
| h3 success rate during attack | 100% |
| h2 recovery success rate | 100% |
| Blocking rule priority | 200 |
| DROP rule hard timeout | 29 seconds |

The eighth SYN is forwarded while a copy is sent to the controller. The controller then detects the threshold and installs the DROP rule, blocking subsequent matching packets.

### Experiment Interpretation

Without dynamic blocking, all 120 attacker connections succeeded during the baseline experiment.

With dynamic blocking enabled, only 8 of the 22 attempted connections succeeded; 14 timed out after the DROP rule was installed.

Legitimate host h3 maintained 100% connection success during the attack, and h2 successfully reconnected after recovery.

The attempt counts are not directly comparable because blocked connection attempts consume time waiting for the 0.4-second socket timeout.

Latency measurements represent successful TCP request-response times in the tested Mininet environment. Results are from one experimental run per condition, not averages across repeated trials.
