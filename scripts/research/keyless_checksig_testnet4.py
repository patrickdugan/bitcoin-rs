"""Acquire public Testnet4 fixtures and validate them in an isolated stock node."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
import time
import urllib.request

GENESIS = '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043'

def digest(data):
    return hashlib.sha256(data).digest()

def hash256(data):
    return digest(digest(data))

def fetch(url):
    request=urllib.request.Request(url, headers={'User-Agent':'Keyless-MSI-Local-Audit/1.0'})
    with urllib.request.urlopen(request, timeout=60) as stream:
        return stream.read()

def compact(data, offset):
    first=data[offset]
    if first < 253:
        return first, offset+1
    size={253:2,254:4,255:8}[first]
    return int.from_bytes(data[offset+1:offset+1+size],'little'),offset+1+size

def transaction(data, start):
    offset=start+4
    witness=data[offset:offset+2]==b'\x00\x01'
    if witness:
        offset+=2
    body_start=offset
    inputs,offset=compact(data,offset)
    for _ in range(inputs):
        offset+=36
        size,offset=compact(data,offset)
        offset+=size+4
    outputs,offset=compact(data,offset)
    scripts=[]
    for _ in range(outputs):
        offset+=8
        size,offset=compact(data,offset)
        scripts.append(data[offset:offset+size].hex())
        offset+=size
    body_end=offset
    witnesses=[]
    witness_ranges=[]
    if witness:
        for _ in range(inputs):
            items,offset=compact(data,offset)
            stack=[]
            for _ in range(items):
                size,offset=compact(data,offset)
                stack.append(data[offset:offset+size].hex())
                witness_ranges.append((offset,size))
                offset+=size
            witnesses.append(stack)
    end=offset+4
    stripped=data[start:start+4]+data[body_start:body_end]+data[offset:end]
    return {'txid':hash256(stripped)[::-1].hex(),'wtxid':hash256(data[start:end])[::-1].hex(),
            'bytes':end-start,'segwit':witness,'raw':data[start:end].hex(),
            'output_scripts':scripts,'witnesses':witnesses,'witness_ranges':witness_ranges},end

def validate_block(raw, expected):
    header=raw[:80]
    assert len(header)==80
    observed=hash256(header)[::-1].hex()
    assert observed==expected,'header hash mismatch'
    bits=struct.unpack_from('<I',header,72)[0]
    target=(bits & 0x7fffff) << (8*((bits>>24)-3))
    assert not bits & 0x800000 and int(observed,16)<=target
    count,offset=compact(raw,80)
    transactions=[]
    for _ in range(count):
        tx,offset=transaction(raw,offset)
        transactions.append(tx)
    assert offset==len(raw)
    level=[bytes.fromhex(tx['txid'])[::-1] for tx in transactions]
    while len(level)>1:
        if len(level)%2:
            level.append(level[-1])
        level=[hash256(level[i]+level[i+1]) for i in range(0,len(level),2)]
    assert level[0]==header[36:68],'transaction merkle mismatch'
    witness_verified=None
    commitments=[bytes.fromhex(script)[6:38] for script in transactions[0]['output_scripts']
                 if len(script)>=76 and script.startswith('6a24aa21a9ed')]
    if commitments:
        reserve=transactions[0]['witnesses']
        assert len(reserve)==1 and len(reserve[0])==1 and len(reserve[0][0])==64,'coinbase witness reserve'
        level=[bytes(32)]+[bytes.fromhex(tx['wtxid'])[::-1] for tx in transactions[1:]]
        while len(level)>1:
            if len(level)%2:
                level.append(level[-1])
            level=[hash256(level[i]+level[i+1]) for i in range(0,len(level),2)]
        assert hash256(level[0]+bytes.fromhex(reserve[0][0]))==commitments[-1],'witness commitment mismatch'
        witness_verified=True
    else:
        assert not any(tx['segwit'] for tx in transactions),'witness without commitment'
    return {'hash':observed,'previous':header[4:36][::-1].hex(),'header':header.hex(),
            'pow_verified':True,'merkle_verified':True,'bytes':len(raw),'tx_count':count,
            'witness_commitment_verified':witness_verified,
            'transactions':transactions,'sha256':digest(raw).hex()}

def main():
    if not __debug__:
        raise RuntimeError('run with Python assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--core',type=pathlib.Path,required=True)
    parser.add_argument('--fixtures',type=pathlib.Path)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('fixture',args.source/'scripts/research/keyless_checksig_rpc.py')
    fixture=importlib.util.module_from_spec(spec)
    sys.modules['fixture']=fixture
    spec.loader.exec_module(fixture)
    base='https://mempool.space/testnet4/api'
    report={'status':'running','scope':'Public fixtures; isolated stock Testnet4 validation; no public broadcasts',
            'genesis_expected':GENESIS,'source_url':base,'blocks':[],
            'command':sys.argv,'harness_sha256':digest(pathlib.Path(__file__).read_bytes()).hex(),
            'fixture_helper_sha256':digest(pathlib.Path(fixture.__file__).read_bytes()).hex(),
            'core_sha256':digest(args.core.read_bytes()).hex(),
            'core_version':subprocess.check_output([str(args.core),'--version'],text=True),
            'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    try:
        prior=json.loads((args.fixtures/'report.json').read_text()) if args.fixtures else None
        if prior:
            assert prior['status']=='passed'
        genesis=prior['public_network_identity_verified'] if prior else fetch(base+'/block-height/0').decode().strip()
        assert genesis==GENESIS,genesis
        report['public_network_identity_verified']=genesis
        report['acquisition']='verified cached public fixtures' if prior else 'public HTTPS API'
        previous=None
        for height in [0,1,2,50000]:
            block_hash=next(b['hash'] for b in prior['blocks'] if b['height']==height) if prior else fetch(base+f'/block-height/{height}').decode().strip()
            raw=(args.fixtures/f'block-{height}.bin').read_bytes() if prior else fetch(base+f'/block/{block_hash}/raw')
            (args.output/f'block-{height}.bin').write_bytes(raw)
            item=validate_block(raw,block_hash)
            item['height']=height
            item['raw_url']=base+f'/block/{block_hash}/raw'
            if height in (1,2):
                assert item['previous']==previous
            previous=block_hash
            report['blocks'].append(item)
        report['mutation_rejections']={}
        for name,height,offset,expected_error in [
            ('header_mutation',1,76,'header hash mismatch'),
            ('transaction_mutation',1,len((args.output/'block-1.bin').read_bytes())-1,'transaction merkle mismatch'),
            ('witness_mutation',50000,next(offset for tx in report['blocks'][-1]['transactions'][1:]
                                         for offset,size in tx['witness_ranges'] if size),'witness commitment mismatch')]:
            raw=bytearray((args.output/f'block-{height}.bin').read_bytes())
            raw[offset]^=1
            expected=next(b['hash'] for b in report['blocks'] if b['height']==height)
            try:
                validate_block(bytes(raw),expected)
            except AssertionError as error:
                assert str(error)==expected_error,(name,str(error))
                report['mutation_rejections'][name]={'height':height,'offset':offset,'failure':str(error)}
            else:
                raise AssertionError(name+' unexpectedly accepted')
        class CoreNode(fixture.Node):
            def start(self):
                command=[str(self.binary),'-testnet4',f'-datadir={self.root}',
                         '-server=1','-listen=0','-connect=0','-dnsseed=0','-discover=0',
                         '-disablewallet=1',f'-rpcport={self.rpc_port}','-rpcbind=127.0.0.1',
                         '-rpcallowip=127.0.0.1','-rpcuser=research',f'-rpcpassword={self.password}']
                self.process=subprocess.Popen(command,stdout=self.log,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    assert self.process.poll() is None,'Core exited during startup'
                    try:
                        return self.rpc('getblockchaininfo')
                    except (OSError,fixture.RpcError):
                        time.sleep(.2)
                raise TimeoutError('Core startup')
        data=args.output/'stock-testnet4'
        data.mkdir()
        node=CoreNode(args.core,data)
        try:
            info=node.start()
            assert info['chain']=='testnet4' and info['blocks']==0
            assert node.rpc('getblockhash',[0])==GENESIS
            assert node.rpc('getconnectioncount')==0
            report['stock_initial']=info
            report['submissions']=[]
            for height in (1,2):
                raw=(args.output/f'block-{height}.bin').read_bytes()
                result=node.rpc('submitblock',[raw.hex()])
                assert result is None,result
                assert node.rpc('getblockcount')==height
                report['submissions'].append({'height':height,'result':result,
                                               'hash':node.rpc('getblockhash',[height])})
            report['stock_final']=node.rpc('getblockchaininfo')
            report['peer_count']=node.rpc('getconnectioncount')
            assert report['peer_count']==0
            report['status']='passed'
        finally:
            process=node.process
            try:
                node.stop()
                report['shutdown_exit_code']=process.returncode if process else None
                assert report['shutdown_exit_code']==0,'stock node shutdown failed'
            finally:
                node.log.close()
        report['boundary']='This validates genuine public blocks on stock Testnet4. Synthetic opcode spends require isolated regtest; they are not public Testnet4 activations.'
    except BaseException as error:
        report.update(status='failed',error=f'{type(error).__name__}: {error}')
        raise
    finally:
        report['finished_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='blocks'},indent=2))

if __name__=='__main__':
    main()
