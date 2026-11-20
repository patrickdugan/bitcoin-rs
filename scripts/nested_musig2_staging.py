import base64
from decimal import Decimal
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class StagingError(RuntimeError):
    pass


class RpcError(StagingError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RpcError("RPC redirects are forbidden")


class Rpc:
    def __init__(self, url, *, cookie=None, credentials=None, timeout=30):
        parsed = urlsplit(url)
        try:
            host = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as error:
            raise StagingError("RPC host must be a literal loopback IP address") from error
        if (
            parsed.scheme != "http"
            or not host.is_loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.port is None
        ):
            raise StagingError("RPC URL must be http://<loopback-IP>:<port>/")
        if (cookie is None) == (credentials is None):
            raise StagingError("supply exactly one RPC credential source")
        self.url = url
        self.cookie = Path(cookie) if cookie is not None else None
        self.credentials = credentials
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, method, *params):
        credentials = self.credentials
        if self.cookie is not None:
            with self.cookie.open(encoding="utf-8") as source:
                credentials = source.read(8193).strip()
            if len(credentials) > 8192:
                raise RpcError("RPC cookie is too large")
        if not credentials or ":" not in credentials:
            raise RpcError("RPC credentials are malformed")
        authorization = base64.b64encode(credentials.encode()).decode("ascii")
        payload = json.dumps(
            {"jsonrpc": "1.0", "id": "nested-musig2", "method": method, "params": params}
        ).encode()
        request = Request(
            self.url,
            data=payload,
            headers={
                "Authorization": "Basic " + authorization,
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(16 * 1024 * 1024 + 1)
        except HTTPError as error:
            body = error.read(16 * 1024 * 1024 + 1)
        if len(body) > 16 * 1024 * 1024:
            raise RpcError(f"{method}: RPC response is too large")
        try:
            result = json.loads(body, parse_float=Decimal)
        except (ValueError, UnicodeDecodeError) as error:
            raise RpcError(f"{method}: RPC response is invalid JSON") from error
        if not isinstance(result, dict):
            raise RpcError(f"{method}: RPC response is invalid")
        if result.get("error") is not None:
            raise RpcError(f"{method}: {result['error']}")
        if "result" not in result:
            raise RpcError(f"{method}: RPC result is absent")
        return result["result"]


def wait_rpc(rpc, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise StagingError(f"node exited with status {process.returncode}")
        try:
            return rpc.call("getblockchaininfo")
        except (OSError, URLError, RpcError):
            time.sleep(0.2)
    raise StagingError("node RPC did not become ready before timeout")


def signer_json(binary, *arguments):
    completed = subprocess.run(
        [str(binary), *map(str, arguments)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise StagingError(f"signer failed: {completed.stderr.strip()}")
    try:
        value = json.loads(completed.stdout)
    except ValueError as error:
        raise StagingError("signer output is invalid JSON") from error
    if not isinstance(value, dict):
        raise StagingError("signer output must be a JSON object")
    return value


def btc_to_sat(value):
    satoshis = Decimal(str(value)) * 100_000_000
    if not satoshis.is_finite() or satoshis != satoshis.to_integral_value():
        raise StagingError("RPC amount is not an exact number of satoshis")
    return int(satoshis)


def assert_chain(rpc, public, expected):
    info = rpc.call("getblockchaininfo")
    if info["chain"] != expected:
        raise StagingError(f"node chain is {info['chain']}, expected {expected}")
    if rpc.call("getblockhash", 0) != public["genesis_hash"]:
        raise StagingError("node genesis does not match the signing network")
    return info


def verified_prevout(rpc, public, txid, vout, amount_sat):
    prevout = rpc.call("gettxout", txid, vout, True)
    if prevout is None:
        raise StagingError("requested outpoint is spent or absent")
    if btc_to_sat(prevout["value"]) != amount_sat:
        raise StagingError("requested amount differs from the node's UTXO value")
    if prevout["scriptPubKey"]["hex"] != public["script_pubkey"]:
        raise StagingError("requested outpoint belongs to another signing tree")
    if prevout.get("confirmations", 0) < 1:
        raise StagingError("requested outpoint must be confirmed")
    if prevout.get("coinbase", False) and prevout["confirmations"] < 100:
        raise StagingError("requested coinbase output is immature")
    return prevout


def make_signature(signer, keys, public, txid, vout, amount, destination, fee, maximum):
    signed = signer_json(
        signer,
        "sign",
        "--network", public["network"],
        "--keys", keys,
        "--txid", txid,
        "--vout", vout,
        "--amount-sat", amount,
        "--prevout-scriptpubkey", public["script_pubkey"],
        "--destination", destination,
        "--fee-sat", fee,
        "--max-fee-sat", maximum,
    )
    if (
        signed["tree"] != public
        or signed["previous_txid"] != txid
        or signed["previous_vout"] != vout
        or signed["input_amount_sat"] != amount
        or signed["destination"] != destination
        or signed["fee_sat"] != fee
        or signed["max_fee_sat"] != maximum
        or signed["output_amount_sat"] != amount - fee
    ):
        raise StagingError("signer output differs from the authorized transaction")
    return signed


def mempool_check(rpc, signed, *, raw=None, allow=True):
    results = rpc.call("testmempoolaccept", [raw or signed["transaction_hex"]])
    if not isinstance(results, list) or len(results) != 1:
        raise StagingError("testmempoolaccept returned an invalid result")
    result = results[0]
    if result.get("allowed") is not allow:
        raise StagingError(f"unexpected mempool verdict: {result}")
    if result.get("txid") != signed["txid"]:
        raise StagingError("mempool verdict transaction ID differs from the signed transaction")
    if allow:
        if result.get("vsize") != signed["vsize"]:
            raise StagingError("node and signer disagree on virtual transaction size")
        if btc_to_sat(result["fees"]["base"]) != signed["fee_sat"]:
            raise StagingError("node and signer disagree on the transaction fee")
    return result


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as destination:
        json.dump(value, destination, indent=2, sort_keys=True, default=str)
        destination.write("\n")


def source_revision():
    packaged_revision = Path(__file__).resolve().parent.parent / "source-sha.txt"
    if packaged_revision.is_file():
        revision = packaged_revision.read_text(encoding="ascii").strip()
        if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
            raise StagingError("packaged source revision is malformed")
        return revision
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parent.parent,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def source_dirty():
    if (Path(__file__).resolve().parent.parent / "source-sha.txt").is_file():
        return None
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=Path(__file__).resolve().parent.parent,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    return bool(result.stdout.strip()) if result.returncode == 0 else None


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
