#!/usr/bin/env python3
"""Run static-OVS baseline and dynamic-SDN comparison in Mininet."""
import os, signal, subprocess, sys, time
from functools import partial
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, OVSBridge
from mininet.log import setLogLevel
from topology import DynamicBlockingTopo

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(ROOT, 'tcp_app.py')
CSV = os.path.join(ROOT, 'performance_results.csv')
LOG = os.path.join(ROOT, 'controller_performance.log')


def traffic(host, rate, seconds, label):
    return host.popen(['python3', APP, 'client', '--host', '10.0.0.4',
        '--rate', str(rate), '--duration', str(seconds), '--label', label,
        '--csv', CSV], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def show(process):
    output, _ = process.communicate(timeout=40)
    print(output, end='')
    if process.returncode:
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
                raise RuntimeError('OS-Ken did not start; check controller log')
        switch = partial(OVSSwitch, protocols='OpenFlow13') if dynamic else OVSBridge
        ctrl = partial(RemoteController, ip='127.0.0.1', port=6653) if dynamic else None
        net = Mininet(topo=DynamicBlockingTopo(), controller=ctrl, switch=switch,
                      autoSetMacs=True, waitConnected=dynamic)
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
            if 'nw_src=10.0.0.2' not in flows or 'actions=drop' not in flows:
                raise RuntimeError('Attacker DROP rule was not found')
            deadline = time.time() + 35
            while time.time() < deadline:
                with open(LOG) as f:
                    if '[UNBLOCK] Host 10.0.0.2' in f.read():
                        break
                time.sleep(.5)
            else:
                raise RuntimeError('Attacker did not recover after cooldown')
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
            controller.wait(timeout=5)
        if log:
            log.close()
        subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if os.geteuid() != 0:
        sys.exit('Run with: sudo python3 performance_test.py')
    setLogLevel('warning')
    if os.path.exists(CSV):
        os.remove(CSV)
    subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    experiment(False)
    experiment(True)
    print('\nCombined measurements:', CSV)
    with open(CSV) as results:
        print(results.read())

if __name__ == '__main__':
    main()
