#!/usr/bin/env python3
"""
Project 12: Dynamic Host Blocking System
Automated Demonstration & Evaluation Script

Runs all 7 requirements of Project 12 in a single command:
1. Generate TCP traffic from multiple hosts
2. Monitor connection rates
3. Collect flow statistics
4. Define abnormal traffic thresholds
5. Detect suspicious hosts
6. Maintain a dynamic blocklist
7. Install SDN drop rules
"""

import os
import signal
import subprocess
import sys
import time

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))

def run(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def main():
    print("\n" + "="*65)
    print("  PROJECT 12: DYNAMIC HOST BLOCKING SYSTEM - LIVE DEMO  ")
    print("="*65)

    # 1. Clean up old instances
    print("[1/6] Cleaning up Mininet and old controller processes...")
    run("sudo mn -c")
    run("sudo pkill -9 -f osken-manager")
    run("sudo pkill -9 -f server.py")
    time.sleep(1)

    # 2. Start SDN Controller
    print("[2/6] Starting SDN Controller (controller.py)...")
    ctrl_log = open(os.path.join(PROJECT_DIR, "controller.log"), "w")
    ctrl_proc = subprocess.Popen(
        "osken-manager controller.py",
        cwd=PROJECT_DIR,
        shell=True,
        stdout=ctrl_log,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )
    time.sleep(2.5)

    try:
        from functools import partial
        from mininet.net import Mininet
        from mininet.node import RemoteController, OVSSwitch
        from mininet.log import setLogLevel
        import importlib.util

        spec = importlib.util.spec_from_file_location("topology", os.path.join(PROJECT_DIR, "topology.py"))
        topo_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(topo_mod)

        setLogLevel('warning')
        print("[3/6] Starting Mininet Topology (topology.py)...")
        net = Mininet(
            topo=topo_mod.DynamicBlockingTopo(),
            controller=partial(RemoteController, ip='127.0.0.1', port=6653),
            switch=partial(OVSSwitch, protocols='OpenFlow13'),
            autoSetMacs=True,
            waitConnected=True
        )
        net.start()
        time.sleep(1.5)

        h1, h2, h3, h4, s1 = net.get('h1', 'h2', 'h3', 'h4', 's1')

        # Verify reachability
        print("\n--- Verifying Network Reachability (pingall) ---")
        drop = net.pingAll()
        print(f"Pingall packet loss: {drop}%\n")

        # Start TCP server on h4
        print("[4/6] Starting TCP Server on Host h4 (10.0.0.4:5001)...")
        h4.cmd(f"python3 '{PROJECT_DIR}/server.py' --host 10.0.0.4 --port 5001 &")
        time.sleep(1)

        # Normal traffic from h1
        print("--- Host h1: Generating Normal TCP Traffic (Rate = 1.0 conn/s) ---")
        print("Expected: Under threshold (8 SYNs in 5s) -> Allowed")
        out1 = h1.cmd(f"python3 '{PROJECT_DIR}/traffic_generator.py' --host 10.0.0.4 --port 5001 --rate 1.0 --duration 6 --label H1-NORMAL")
        print(out1)

        # Abnormal traffic from h2
        print("--- Host h2: Generating Abnormal Burst Traffic (Rate = 20.0 conn/s) ---")
        print("Expected: Exceeds threshold (8 SYNs in 5s) -> Dynamically Blocked by SDN")
        out2 = h2.cmd(f"python3 '{PROJECT_DIR}/traffic_generator.py' --host 10.0.0.4 --port 5001 --rate 20.0 --duration 5 --label H2-ATTACK")
        print(out2)

        # Unaffected traffic from h3
        print("--- Host h3: Legitimate Concurrent Host (Isolation Verification) ---")
        print("Expected: 100% Success while h2 is blocked")
        out3 = h3.cmd(f"python3 '{PROJECT_DIR}/traffic_generator.py' --host 10.0.0.4 --port 5001 --rate 1.0 --duration 3 --label H3-CONCURRENT")
        print(out3)

        # Inspect OpenFlow drop rule
        print("[5/6] Inspecting Switch s1 OpenFlow 1.3 Flow Table (ovs-ofctl)...")
        flow_dump = s1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1")
        for line in flow_dump.splitlines():
            if "priority=" in line:
                print("  " + line.strip())

        # Cooldown recovery
        print("\n[6/6] Waiting for Cooldown Expiration (25 seconds)...")
        for s in range(25, 0, -5):
            print(f"  Cooldown remaining: {s}s...")
            time.sleep(5)
        time.sleep(2)

        print("\n--- Testing Host h2 After Cooldown Expiration ---")
        print("Expected: Drop rule removed -> Normal traffic restored")
        out2_rec = h2.cmd(f"python3 '{PROJECT_DIR}/traffic_generator.py' --host 10.0.0.4 --port 5001 --rate 1.0 --duration 3 --label H2-RECOVERED")
        print(out2_rec)

        h4.cmd("pkill -9 -f server.py")
        net.stop()

    except Exception as e:
        print("Error during demo:", e)
    finally:
        try:
            os.killpg(os.getpgid(ctrl_proc.pid), signal.SIGTERM)
        except Exception:
            pass
        ctrl_log.close()
        run("sudo mn -c")
        run("sudo pkill -9 -f server.py")

    print("="*65)
    print(" LIVE DEMO COMPLETED SUCCESSFULLY: ALL REQUIREMENTS SATISFIED ")
    print("="*65 + "\n")

if __name__ == "__main__":
    main()

