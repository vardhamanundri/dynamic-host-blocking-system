#!/usr/bin/env python3
"""Small threaded TCP server and rate-controlled TCP traffic client."""
import argparse
import csv
import math
import os
import socket
import threading
import time


def serve(conn):
    with conn:
        try:
            data = conn.recv(1024)
            if data:
                conn.sendall(b'ACK:' + data)
        except OSError:
            pass


def run_server(host, port):
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(128)
        print(f'TCP server listening on {host}:{port}')
        while True:
            conn, _ = server.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()


def run_client(args):
    start, end = time.monotonic(), time.monotonic() + args.duration
    counts = dict(attempts=0, success=0, timeouts=0, refused=0, errors=0)
    latencies, first_failure = [], ''
    while time.monotonic() < end:
        tick = time.monotonic()
        counts['attempts'] += 1
        try:
            with socket.create_connection((args.host, args.port), timeout=.4) as s:
                s.sendall(b'PING\n')
                if not s.recv(64):
                    raise OSError('empty reply')
            counts['success'] += 1
            latencies.append((time.monotonic() - tick) * 1000)
        except socket.timeout:
            counts['timeouts'] += 1
            first_failure = first_failure or round(time.monotonic() - start, 2)
        except ConnectionRefusedError:
            counts['refused'] += 1
            first_failure = first_failure or round(time.monotonic() - start, 2)
        except OSError:
            counts['errors'] += 1
            first_failure = first_failure or round(time.monotonic() - start, 2)
        time.sleep(max(0, 1 / args.rate - (time.monotonic() - tick)))
    rate = 100 * counts['success'] / counts['attempts'] if counts['attempts'] else 0
    ordered = sorted(latencies)
    p95 = ordered[max(0, math.ceil(.95 * len(ordered)) - 1)] if ordered else 0
    avg = sum(ordered) / len(ordered) if ordered else 0
    print(f"{args.label}: {counts}, success={rate:.1f}%, avg={avg:.2f}ms, p95={p95:.2f}ms")
    if args.csv:
        row = dict(label=args.label, target=f'{args.host}:{args.port}', **counts,
                   success_rate=round(rate, 2), avg_ms=round(avg, 2),
                   p95_ms=round(p95, 2), first_failure_s=first_failure)
        new = not os.path.exists(args.csv) or not os.path.getsize(args.csv)
        with open(args.csv, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            if new:
                writer.writeheader()
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest='mode', required=True)
    server = modes.add_parser('server')
    server.add_argument('--host', default='0.0.0.0')
    server.add_argument('--port', type=int, default=5001)
    client = modes.add_parser('client')
    client.add_argument('--host', required=True)
    client.add_argument('--port', type=int, default=5001)
    client.add_argument('--rate', type=float, default=1)
    client.add_argument('--duration', type=float, default=6)
    client.add_argument('--label', default='CLIENT')
    client.add_argument('--csv')
    args = parser.parse_args()
    if args.mode == 'server':
        run_server(args.host, args.port)
    elif args.rate <= 0 or args.duration <= 0:
        parser.error('rate and duration must be positive')
    else:
        run_client(args)

if __name__ == '__main__':
    main()
