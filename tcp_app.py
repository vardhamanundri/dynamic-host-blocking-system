#!/usr/bin/env python3
"""Concurrent TCP server and rate-controlled client for the Mininet hosts."""
import argparse
import csv
import os
import socket
import threading
import time


def handle(conn):
    with conn:
        conn.settimeout(5)
        try:
            data = conn.recv(1024)
            if data:
                conn.sendall(b'ACK:' + data)
        except OSError:
            pass


def server(host, port):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        print(f'TCP server listening on {host}:{port}')
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()


def client(args):
    start = time.monotonic()
    counts = dict(attempts=0, success=0, timeouts=0, refused=0, errors=0)
    latencies, first_failure = [], ''
    while time.monotonic() < start + args.duration:
        tick = time.monotonic()
        counts['attempts'] += 1
        try:
            with socket.create_connection((args.host, args.port), timeout=.4) as sock:
                sock.sendall(b'PING\n')
                if not sock.recv(64):
                    raise OSError('empty reply')
            counts['success'] += 1
            latencies.append((time.monotonic() - tick) * 1000)
        except OSError as err:
            key = ('timeouts' if isinstance(err, socket.timeout) else
                   'refused' if isinstance(err, ConnectionRefusedError) else 'errors')
            counts[key] += 1
            if not first_failure:
                first_failure = round(time.monotonic() - start, 2)
        time.sleep(max(0, 1 / args.rate - (time.monotonic() - tick)))
    rate = 100 * counts['success'] / counts['attempts']
    average = sum(latencies) / len(latencies) if latencies else 0
    print(f"{args.label}: {counts}, success={rate:.1f}%, avg={average:.2f}ms")
    if args.csv:
        row = dict(label=args.label, target=f'{args.host}:{args.port}', **counts,
                   success_rate=round(rate, 2), avg_ms=round(average, 2),
                   first_failure_s=first_failure)
        new = not os.path.exists(args.csv) or not os.path.getsize(args.csv)
        with open(args.csv, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=row.keys())
            if new:
                writer.writeheader()
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest='mode', required=True)
    s = modes.add_parser('server')
    s.add_argument('--host', default='0.0.0.0')
    s.add_argument('--port', type=int, default=5001)
    c = modes.add_parser('client')
    c.add_argument('--host', required=True)
    c.add_argument('--port', type=int, default=5001)
    c.add_argument('--rate', type=float, default=1)
    c.add_argument('--duration', type=float, default=6)
    c.add_argument('--label', default='CLIENT')
    c.add_argument('--csv')
    args = parser.parse_args()
    if args.mode == 'server':
        server(args.host, args.port)
    elif args.rate <= 0 or args.duration <= 0:
        parser.error('rate and duration must be positive')
    else:
        client(args)


if __name__ == '__main__':
    main()
