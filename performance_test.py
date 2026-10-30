#!/usr/bin/env python3

import csv
import os
import signal
import subprocess
import sys
import time
from functools import partial

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TOPOLOGY_FILE = os.path.join(PROJECT_DIR, "topology.py")
SERVER_FILE = os.path.join(PROJECT_DIR, "server.py")
GENERATOR_FILE = os.path.join(PROJECT_DIR, "traffic_generator.py")

RESULTS = {
    "baseline_h1": "baseline_h1.csv",
    "baseline_attack": "baseline_attack.csv",
    "baseline_legitimate": "baseline_legitimate.csv",
    "dynamic_h1": "dynamic_h1.csv",
    "dynamic_attack": "dynamic_attack.csv",
    "dynamic_legitimate": "dynamic_legitimate.csv",
    "dynamic_recovery": "dynamic_recovery.csv",
}

def cleanup():
    subprocess.run(
        ["mn", "-c"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )

def start_traffic(host, rate, duration, label, csv_file):
    command = [
        "python3", GENERATOR_FILE,
        "--host", "10.0.0.4",
        "--port", "5001",
        "--rate", str(rate),
        "--duration", str(duration),
        "--label", label,
        "--csv", csv_file
    ]

    return host.popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

def finish_traffic(process, duration):
    output, _ = process.communicate(timeout=duration + 30)
    print(output)

    if process.returncode != 0:
        raise RuntimeError(
            f"Traffic generator exited with code {process.returncode}"
        )

def run_experiment(mode):
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch, OVSBridge
    from mininet.log import setLogLevel
    import importlib.util

    baseline = mode == "baseline"
    title = "BASELINE: STATIC OVS" if baseline else "PROPOSED: DYNAMIC SDN"

    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)

    controller = None
    controller_log = None
    server_log = None
    server = None
    net = None

    try:
        if not baseline:
            controller_log = open(
                os.path.join(PROJECT_DIR, "controller_performance.log"),
                "w"
            )

            controller = subprocess.Popen(
                ["osken-manager", "controller.py"],
                cwd=PROJECT_DIR,
                stdout=controller_log,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )

            time.sleep(2.5)

            if controller.poll() is not None:
                raise RuntimeError(
                    "OS-Ken controller failed to start. "
                    "Check controller_performance.log"
                )

        spec = importlib.util.spec_from_file_location(
            "project_topology", TOPOLOGY_FILE
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        setLogLevel("warning")

        if baseline:
            net = Mininet(
                topo=module.DynamicBlockingTopo(),
                controller=None,
                switch=OVSBridge,
                autoSetMacs=True
            )
        else:
            net = Mininet(
                topo=module.DynamicBlockingTopo(),
                controller=partial(
                    RemoteController, ip="127.0.0.1", port=6653
                ),
                switch=partial(OVSSwitch, protocols="OpenFlow13"),
                autoSetMacs=True,
                waitConnected=True
            )

        print("[1] Starting four-host Mininet topology...")
        net.start()
        time.sleep(2)

        if not baseline:
            with open(
                os.path.join(PROJECT_DIR, "controller_performance.log")
            ) as f:
                if "[SWITCH] Connected" not in f.read():
                    raise RuntimeError(
                        "Controller did not confirm switch connection"
                    )

        h1, h2, h3, h4, s1 = net.get(
            "h1", "h2", "h3", "h4", "s1"
        )

        print("\n[2] Checking network connectivity...")
        loss = net.pingAll()
        print(f"Initial ping packet loss: {loss}%")

        if loss > 0:
            raise RuntimeError("Initial host connectivity test failed")

        print("\n[3] Starting TCP server on h4...")
        server_log = open(
            os.path.join(PROJECT_DIR, f"server_{mode}_performance.log"),
            "w"
        )

        server = h4.popen(
            [
                "python3", SERVER_FILE,
                "--host", "10.0.0.4",
                "--port", "5001"
            ],
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True
        )

        time.sleep(1)

        if server.poll() is not None:
            raise RuntimeError("TCP server failed to start")

        prefix = "baseline" if baseline else "dynamic"

        print("\n[4] Testing normal traffic from h1...")
        p = start_traffic(
            h1, 1, 3, prefix.upper() + "-H1",
            os.path.join(PROJECT_DIR, RESULTS[prefix + "_h1"])
        )
        finish_traffic(p, 3)

        print("\n[5] Running h2 attack and h3 legitimate traffic concurrently...")
        print("h2: 20 TCP connections/second")
        print("h3: 1 TCP connection/second")

        p2 = start_traffic(
            h2, 20, 6, prefix.upper() + "-ATTACK",
            os.path.join(PROJECT_DIR, RESULTS[prefix + "_attack"])
        )

        p3 = start_traffic(
            h3, 1, 6, prefix.upper() + "-LEGITIMATE",
            os.path.join(PROJECT_DIR, RESULTS[prefix + "_legitimate"])
        )

        # Both processes run simultaneously.
        finish_traffic(p2, 6)
        finish_traffic(p3, 6)

        if not baseline:
            print("\n[6] Inspecting active OpenFlow DROP rule...")
            flows = s1.cmd(
                "ovs-ofctl -O OpenFlow13 dump-flows s1"
            )

            drop_rules = [
                line for line in flows.splitlines()
                if "priority=200" in line
            ]

            if drop_rules:
                for rule in drop_rules:
                    print(rule.strip())
            else:
                raise RuntimeError("Expected dynamic DROP rule not found")

            print("\n[7] Waiting for automatic cooldown recovery...")

            controller_log_path = os.path.join(
                PROJECT_DIR, "controller_performance.log"
            )

            deadline = time.time() + 35
            recovered = False

            while time.time() < deadline:
                with open(controller_log_path) as f:
                    log_content = f.read()

                if "[UNBLOCK] Host 10.0.0.2" in log_content:
                    recovered = True
                    break

                time.sleep(0.5)

            if not recovered:
                raise RuntimeError(
                    "Controller did not report automatic recovery"
                )

            print("[SUCCESS] Controller automatically unblocked h2.")

            print("\n[8] Testing h2 after recovery...")
            p = start_traffic(
                h2, 1, 3, "DYNAMIC-RECOVERY",
                os.path.join(PROJECT_DIR, RESULTS["dynamic_recovery"])
            )
            finish_traffic(p, 3)

        print(f"\n{title} EXPERIMENT COMPLETED.")

    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

        if net is not None:
            net.stop()

        if controller is not None:
            try:
                os.killpg(controller.pid, signal.SIGTERM)
                controller.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                controller.kill()

        if server_log is not None:
            server_log.close()

        if controller_log is not None:
            controller_log.close()

        cleanup()

def combine_results():
    output_file = os.path.join(PROJECT_DIR, "performance_results.csv")

    labels = {
        "baseline_h1": "Baseline - Normal h1",
        "baseline_attack": "Baseline - Attack h2",
        "baseline_legitimate": "Baseline - Legitimate h3",
        "dynamic_h1": "Dynamic - Normal h1",
        "dynamic_attack": "Dynamic - Attack h2",
        "dynamic_legitimate": "Dynamic - Legitimate h3",
        "dynamic_recovery": "Dynamic - Recovery h2",
    }

    rows = []

    for key, filename in RESULTS.items():
        path = os.path.join(PROJECT_DIR, filename)

        if not os.path.exists(path):
            continue

        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                row["experiment"] = labels[key]
                rows.append(row)

    if not rows:
        raise RuntimeError("No experiment results were generated")

    fields = ["experiment"] + [
        key for key in rows[0] if key != "experiment"
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print("\n" + "=" * 65)
    print("PERFORMANCE COMPARISON")
    print("=" * 65)
    print(
        f"{'Experiment':<34} {'Attempts':>8} "
        f"{'Success':>8} {'Success %':>10} {'Avg ms':>9}"
    )
    print("-" * 75)

    for row in rows:
        print(
            f"{row['experiment']:<34} "
            f"{row['attempts']:>8} "
            f"{row['success']:>8} "
            f"{row['success_rate_percent']:>9}% "
            f"{row['average_latency_ms']:>8}"
        )

    print("-" * 75)
    print(f"\nCombined results saved to: {output_file}")

def main():
    if os.geteuid() != 0:
        print("Run this script with: sudo python3 performance_test.py")
        sys.exit(1)

    # Remove old results so this run has a clean dataset.
    for filename in list(RESULTS.values()) + ["performance_results.csv"]:
        path = os.path.join(PROJECT_DIR, filename)
        if os.path.exists(path):
            os.remove(path)

    cleanup()

    try:
        run_experiment("baseline")
        run_experiment("dynamic")
        combine_results()

        print("\nALL PERFORMANCE EXPERIMENTS COMPLETED SUCCESSFULLY.")

    except Exception as exc:
        print(f"\nPERFORMANCE EXPERIMENT FAILED: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
