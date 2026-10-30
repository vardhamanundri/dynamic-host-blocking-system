#!/usr/bin/env python3
"""Compare static OVS forwarding with dynamic SDN host blocking."""
import os
import signal
import subprocess
import sys
import time
from functools import partial
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge, OVSSwitch, RemoteController
from topology import DynamicBlockingTopo

ROOT = os.path.dirname(os.path.abspath(__file__))
APP, CSV, LOG = (os.path.join(ROOT, f) for f in
                 ('tcp_app.py', 'performance_results.csv', 'controller_performance.log'))


def log_text():
    with open(LOG) as file:
        return file.read()

def traffic(host, rate, seconds, label):
    return host.popen(['python3', APP, 'client', '--host', '10.0.0.4',
        '--rate', str(rate), '--duration', str(seconds), '--label', label,
        '--csv', CSV], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def show(proc):
    output, _ = proc.communicate(timeout=40)
    print(output, end='')
    if proc.returncode:
        raise RuntimeError('TCP traffic process failed')


def experiment(dynamic):
    controller = log = net = server = None
    try:
        if dynamic:
            log = open(LOG, 'w')
            controller = subprocess.Popen(['osken-manager', 'controller.py'],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(2)
            if controller.poll() is not None:
                raise RuntimeError('OS-Ken failed; inspect controller_performance.log')
        ctrl = partial(RemoteController, ip='127.0.0.1', port=6653) if dynamic else None
        net = Mininet(topo=DynamicBlockingTopo(), controller=ctrl,
            switch=OVSSwitch if dynamic else OVSBridge, waitConnected=dynamic)
        net.start()
        if net.pingAll() != 0:
            raise RuntimeError('Mininet connectivity test failed')
        h1, h2, h3, h4, s1 = net.get('h1', 'h2', 'h3', 'h4', 's1')
        server = h4.popen(['python3', APP, 'server', '--host', '10.0.0.4'])
        time.sleep(1)
        tag = 'DYNAMIC' if dynamic else 'BASELINE'
        show(traffic(h1, 1, 3, tag + '-NORMAL'))
        attacker = traffic(h2, 20, 6, tag + '-ATTACK')
        legitimate = traffic(h3, 1, 6, tag + '-LEGITIMATE')
        show(attacker)
        show(legitimate)
        if dynamic:
            flows = s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
            drops = [line for line in flows.splitlines() if 'actions=drop' in line]
            if not any('nw_src=10.0.0.2' in line for line in drops):
                raise RuntimeError('Attacker DROP rule not found')
            if any('nw_src=10.0.0.3' in line for line in drops):
                raise RuntimeError('Legitimate host h3 was blocked')
            print('Verified DROP rule:', *drops, sep='\n')
            deadline = time.time() + 40
            while '[UNBLOCK] Host 10.0.0.2' not in log_text():
                if time.time() > deadline:
                    raise RuntimeError('Attacker did not recover')
                time.sleep(.5)
            logs = log_text()
            if '[FLOW-STAT]' not in logs or '[ALERT]' not in logs:
                raise RuntimeError('Detection or flow statistics were not logged')
            show(traffic(h2, 1, 3, 'RECOVERY-H2'))
    finally:
        if server:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
        if net:
            net.stop()
        if controller:
            os.killpg(controller.pid, signal.SIGTERM)
            try:
                controller.wait(timeout=5)
            except subprocess.TimeoutExpired:
                controller.kill()
        if log:
            log.close()
        subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if os.geteuid() != 0:
        sys.exit('Run: sudo python3 performance_test.py')
    setLogLevel('warning')
    if os.path.exists(CSV):
        os.remove(CSV)
    subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    experiment(False)
    experiment(True)
    print('\nFresh measurements:', CSV)
    print(open(CSV).read())


if __name__ == '__main__':
    main()
