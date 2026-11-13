"""Isolated regtest node management for the MULADDMOD campaign."""
from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


class RpcError(RuntimeError):
    def __init__(self, method, error):
        super().__init__(f'{method}: {error}')
        self.method = method
        self.error = error


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Node:
    """A bitcoin-rs (or bitcoind) regtest process bound to loopback."""

    def __init__(self, binary: Path, root: Path, name: str = 'node', kind: str = 'bitcoin-rs',
                 extra_args: list | None = None):
        self.binary = Path(binary)
        self.root = Path(root) / name
        self.root.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.kind = kind
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        while self.p2p_port == self.rpc_port:
            self.p2p_port = free_port()
        self.process = None
        self.extra_args = list(extra_args or [])
        self.log_path = self.root / 'node.log'
        self.user, self.password = 'campaign', 'isolated-regtest-only'

    # ------------------------------------------------------------- rpc
    def rpc(self, method, *params, timeout=120):
        auth = base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        body = json.dumps({'jsonrpc': '1.0' if self.kind == 'core' else '2.0', 'id': 1,
                           'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{self.rpc_port}/', body,
                                     headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + auth})
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as err:
            resp = err
        with resp:
            raw = resp.read()
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            raise RpcError(method, {'http': raw.decode(errors='replace')})
        if result.get('error'):
            raise RpcError(method, result['error'])
        return result['result']

    def try_rpc(self, method, *params, timeout=120):
        try:
            return True, self.rpc(method, *params, timeout=timeout)
        except RpcError as err:
            return False, err.error

    # ------------------------------------------------------------- lifecycle
    def command(self):
        if self.kind == 'core':
            return [str(self.binary), '-regtest', f'-datadir={self.root / "data"}', f'-port={self.p2p_port}',
                    f'-rpcport={self.rpc_port}', '-bind=127.0.0.1', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
                    f'-rpcuser={self.user}', f'-rpcpassword={self.password}', '-dnsseed=0', '-listenonion=0',
                    '-fixedseeds=0', '-discover=0', '-printtoconsole=1', '-fallbackfee=0.0002',
                    '-txindex=1', *self.extra_args]
        return [str(self.binary), '--network', 'regtest', '--validation-engine', 'native',
                '--storage-backend', 'fjall', '--data-dir', str(self.root / 'data'),
                '--p2p-listen', f'127.0.0.1:{self.p2p_port}', '--rpc-bind', f'127.0.0.1:{self.rpc_port}',
                '--dns-seeds-enabled=false', '--rpc-user', self.user, '--rpc-password', self.password,
                '--txindex', 'true', *self.extra_args]

    def start(self, timeout=120):
        (self.root / 'data').mkdir(parents=True, exist_ok=True)
        log = self.log_path.open('ab')
        self.process = subprocess.Popen(self.command(), stdout=log, stderr=subprocess.STDOUT)
        log.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f'{self.name} exited during startup; see {self.log_path}')
            try:
                return self.rpc('getblockchaininfo', timeout=5)
            except (OSError, RpcError):
                time.sleep(0.2)
        raise TimeoutError(f'{self.name} RPC startup')

    def stop(self, graceful=True, timeout=60):
        if self.process is None or self.process.poll() is not None:
            self.process = None
            return
        if graceful:
            try:
                self.rpc('stop', timeout=10)
            except Exception:
                self.process.send_signal(signal.SIGTERM)
        else:
            self.process.kill()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.process = None

    def crash(self):
        """SIGKILL without shutdown: models power loss."""
        self.stop(graceful=False)

    # ------------------------------------------------------------- helpers
    def height(self):
        return self.rpc('getblockcount')

    def tip(self):
        return self.rpc('getbestblockhash')

    def mine(self, n, address):
        return self.rpc('generatetoaddress', n, address)

    def mempool(self):
        return set(self.rpc('getrawmempool'))

    def wait_for(self, predicate, timeout=60, what='condition'):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                last = predicate()
                if last:
                    return last
            except (OSError, RpcError) as err:
                last = err
            time.sleep(0.25)
        raise TimeoutError(f'{self.name}: {what} (last={last!r})')
