#!/usr/bin/env python3
"""
Project 12: Dynamic Host Blocking System
TCP Socket Server

Listens on port 5001 and handles concurrent connections from multiple hosts.
"""

import argparse
import socket
import threading

def handle_client(conn, addr):
    try:
        conn.settimeout(3.0)
        data = conn.recv(1024)
        if data:
            conn.sendall(b"ACK:" + data)
    except Exception:
        pass
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="TCP Socket Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001, help="Port to listen on (default: 5001)")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(128)

    print(f"[SERVER] TCP Server listening on {args.host}:{args.port}", flush=True)

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception:
            break

    server.close()
    print("[SERVER] Stopped.", flush=True)

if __name__ == "__main__":
    main()

