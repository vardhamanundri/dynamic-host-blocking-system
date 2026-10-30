import argparse
import csv
import math
import os
import socket
import time


def percentile(values, p):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(p * len(ordered)) - 1)
    return ordered[index]


def run(host, port, rate, duration, label, csv_path=None):
    interval = (1.0 / rate) if rate > 0 else 0.05
    deadline = time.monotonic() + duration
    start = time.monotonic()

    attempts = 0
    success = 0
    timeouts = 0
    refused = 0
    other_errors = 0

    latencies = []
    first_failure = None

    print(
        f"\n[{label}] Target={host}:{port} | "
        f"Rate={rate}/s | Duration={duration}s",
        flush=True
    )

    while time.monotonic() < deadline:
        attempt_start = time.monotonic()
        attempts += 1

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)

        try:
            s.connect((host, port))
            s.sendall(b"PING\n")

            response = s.recv(64)
            if not response:
                raise ConnectionError("Server returned empty response")

            elapsed_ms = (time.monotonic() - attempt_start) * 1000
            latencies.append(elapsed_ms)
            success += 1

            print(
                f"[{label}] Conn #{attempts:02d}: "
                f"SUCCESS ({elapsed_ms:.2f} ms)",
                flush=True
            )

        except socket.timeout:
            timeouts += 1
            status = "TIMEOUT"
            if first_failure is None:
                first_failure = time.monotonic() - start

            print(f"[{label}] Conn #{attempts:02d}: TIMEOUT", flush=True)

        except ConnectionRefusedError:
            refused += 1
            if first_failure is None:
                first_failure = time.monotonic() - start

            print(f"[{label}] Conn #{attempts:02d}: REFUSED", flush=True)

        except OSError as exc:
            other_errors += 1
            if first_failure is None:
                first_failure = time.monotonic() - start

            print(
                f"[{label}] Conn #{attempts:02d}: "
                f"OTHER ERROR ({exc})",
                flush=True
            )

        finally:
            s.close()

        sleep_time = interval - (time.monotonic() - attempt_start)
        if sleep_time > 0:
            time.sleep(sleep_time)

    actual_duration = time.monotonic() - start
    success_rate = (success / attempts * 100) if attempts else 0
    avg_latency = (
        sum(latencies) / len(latencies) if latencies else 0
    )
    p95_latency = percentile(latencies, 0.95)

    print("\n" + "=" * 48)
    print(f" PERFORMANCE SUMMARY: {label}")
    print("=" * 48)
    print(f"Total attempts       : {attempts}")
    print(f"Successful           : {success}")
    print(f"Timeouts             : {timeouts}")
    print(f"Connection refused   : {refused}")
    print(f"Other errors         : {other_errors}")
    print(f"Success rate         : {success_rate:.2f}%")
    print(f"Average latency      : {avg_latency:.2f} ms")
    print(f"95th percentile      : {p95_latency:.2f} ms")
    print(f"Actual duration      : {actual_duration:.2f} s")

    if first_failure is not None:
        print(f"First failure        : {first_failure:.2f} s")

    print("=" * 48, flush=True)

    if csv_path:
        row = {
            "label": label,
            "target": f"{host}:{port}",
            "requested_rate": rate,
            "requested_duration": duration,
            "attempts": attempts,
            "success": success,
            "timeouts": timeouts,
            "refused": refused,
            "other_errors": other_errors,
            "success_rate_percent": round(success_rate, 2),
            "average_latency_ms": round(avg_latency, 2),
            "p95_latency_ms": round(p95_latency, 2),
            "actual_duration_seconds": round(actual_duration, 2),
            "first_failure_seconds": (
                round(first_failure, 2)
                if first_failure is not None else ""
            )
        }

        try:
            exists = os.path.exists(csv_path) and os.path.getsize(csv_path) > 0

            with open(csv_path, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=row.keys())

                if not exists:
                    writer.writeheader()

                writer.writerow(row)

            print(f"\nResults saved to: {csv_path}", flush=True)

        except OSError as exc:
            print(f"CSV export failed: {exc}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="TCP Performance Traffic Generator")

    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--rate", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=6.0)
    parser.add_argument("--label", default="CLIENT")
    parser.add_argument("--csv", default=None)

    args = parser.parse_args()

    run(
        args.host,
        args.port,
        args.rate,
        args.duration,
        args.label,
        args.csv
    )


if __name__ == "__main__":
    main()
