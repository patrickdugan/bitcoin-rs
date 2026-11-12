"""Bounded live opcode, layout, annex, and restart checks on isolated regtest."""
import argparse
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time
import tempfile

REGTEST_GENESIS='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_fixture(source):
    spec=importlib.util.spec_from_file_location('keyless_fixture',source/'scripts/research/keyless_checksig_rpc.py')
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module

def core_class(f):
    class CoreNode(f.Node):
        def start(self):
            command=[str(self.binary),'-regtest',f'-datadir={self.root}','-server=1',
                     '-listen=0','-connect=0','-dnsseed=0','-discover=0','-disablewallet=1',
                     f'-rpcport={self.rpc_port}','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1',
                     '-rpcuser=research',f'-rpcpassword={self.password}']
            self.process=subprocess.Popen(command,stdout=self.log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                require(self.process.poll() is None,'Core exited during startup')
                try:
                    return self.rpc('getblockchaininfo')
                except (OSError,f.RpcError):
                    time.sleep(.2)
            raise TimeoutError('Core startup')
    return CoreNode

def finish(node,directory,output,report):
    try:
        node.stop()
    except BaseException as error:
        report.update(status='failed',shutdown_error=f'{type(error).__name__}: {error}')
        raise
    finally:
        node.log.close()
        codes=getattr(node,'exit_codes',None)
        report['node_exit_codes']=codes
        report['clean_shutdowns']=bool(codes) and all(code==0 for code in codes)
        if not report['clean_shutdowns']:
            report.update(status='failed',shutdown_error='clean node exit evidence is missing')
        shutil.copyfile(Path(directory.name)/'node.log',output/'node.log')
        report['finished_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        directory.cleanup()
    require(report['clean_shutdowns'],'clean node exit evidence is missing')

def fund(f,node,leaves,report):
    rpc=node.rpc
    info=node.start()
    require(info['chain']=='regtest' and info['blocks']==0,'fresh regtest required')
    require(rpc('getblockhash',[0])==REGTEST_GENESIS,'regtest genesis differs')
    require(rpc('getconnectioncount')==0,'unexpected peer')
    base=f.Leaf(b'\x51')
    base_spk,base_control=base.output()
    address=f.address(base_spk[2:])
    blocks=rpc('generatetoaddress',[101,address])
    coinbase=rpc('getblock',[blocks[0],2])['tx'][0]
    output=next(x for x in coinbase['vout'] if x['scriptPubKey']['hex']==base_spk.hex())
    amount=f.satoshis(output['value'])
    outputs=tuple(f.Output(f.AMOUNT,leaf.output()[0]) for leaf in leaves)
    outputs+=(f.Output(amount-len(leaves)*f.AMOUNT-f.FEE,base_spk),)
    tx=f.Tx((f.Input(bytes.fromhex(coinbase['txid'])[::-1],output['n'],amount,base_spk),),outputs)
    raw,txid=tx.serialize([[base.script,base_control]])
    require(rpc('sendrawtransaction',[raw])==txid,'funding txid differs')
    block=rpc('generatetoaddress',[1,address])[0]
    require(txid in rpc('getblock',[block])['tx'],'funding missing from block')
    report.update(network='regtest',genesis=REGTEST_GENESIS,funding_txid=txid,
                  funding_raw=raw,funding_block=block,funding_height=rpc('getblockcount'))
    return txid,address,base,base_spk,base_control

def record_tx(f,tx,stacks):
    raw,txid=tx.serialize(stacks)
    return {'raw':raw,'txid':txid}

def rejected(f,node,address,name,tx,stacks,report):
    item=record_tx(f,tx,stacks)
    item['dry_run']=node.rpc('testmempoolaccept',[[item['raw']]])[0]
    require(item['dry_run']['allowed'] is False,name+' passed mempool')
    before=node.rpc('getblockcount')
    try:
        node.rpc('generateblock',[address,[item['raw']]])
    except f.RpcError as error:
        item['block_error']=error.error
        require('script' in str(error.error).lower(),name+' failed before Script validation')
    else:
        raise ValueError(name+' entered a block')
    after=node.rpc('getblockcount')
    require(after==before,name+' changed height')
    item.update(height_before=before,height_after=after)
    report.setdefault('rejected',{})[name]=item

def accepted(f,node,address,name,tx,stacks,report,confirm=False):
    item=record_tx(f,tx,stacks)
    item['dry_run']=node.rpc('testmempoolaccept',[[item['raw']]])[0]
    if confirm:
        block=node.rpc('generateblock',[address,[item['raw']]])['hash']
        require(item['txid'] in node.rpc('getblock',[block])['tx'],name+' missing from block')
        item.update(block=block,height=node.rpc('getblockcount'))
        item['block_raw']=node.rpc('getblock',[block,0])
    else:
        require(item['dry_run']['allowed'] is True,name+' rejected by mempool')
    report.setdefault('accepted',{})[name]=item
    return item

def stock(f,binary,output):
    output.mkdir(parents=True)
    directory=tempfile.TemporaryDirectory(prefix='keyless-stock-controls-')
    root=Path(directory.name)
    node=core_class(f)(binary,root)
    report={'status':'running','binary_sha256':sha256(binary),'scope':'Stock Core old BIP342 semantics on isolated regtest',
            'command':sys.argv,'harness_sha256':sha256(Path(__file__)),
            'fixture_helper_sha256':sha256(Path(f.__file__)),
            'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    try:
        key=f.push(f.TXCOMMIT_KEY)
        leaves=[f.Leaf(key+b'\xac'),f.Leaf(b'\x7e\x00')]
        funding,address,_,_,_=fund(f,node,leaves,report)
        for index,(name,stack) in enumerate([('unknown_txcommit_key_accepts_one_byte',[b'\x01']),
                                              ('cat_remains_op_success',[])]):
            leaf=leaves[index]
            spk,control=leaf.output()
            tx=f.Tx((f.Input(bytes.fromhex(funding)[::-1],index,f.AMOUNT,spk),),
                    (f.Output(f.PAYOUT,b'\x51\x20'+f.RECIPIENTS[0]),))
            item=accepted(f,node,address,name,tx,[stack+[leaf.script,control]],report,confirm=True)
            require(item['dry_run']['allowed'] is False,'stock relay policy unexpectedly accepted upgrade hook')
        report.update(status='passed',peer_count=node.rpc('getconnectioncount'))
        require(report['peer_count']==0,'unexpected stock peer')
    except BaseException as error:
        report.update(status='failed',error=f'{type(error).__name__}: {error}')
        raise
    finally:
        finish(node,directory,output,report)
    return report

def patched(f,binary,output,public_report):
    output.mkdir(parents=True)
    directory=tempfile.TemporaryDirectory(prefix='keyless-patched-adversarial-')
    root=Path(directory.name)
    node=f.Node(binary,root)
    public=json.loads(public_report.read_text())
    require(public['status']=='passed','public fixtures not verified')
    public_block=next(x for x in public['blocks'] if x['height']==50000)
    annex=b'\x50'+bytes.fromhex(public_block['hash'])
    report={'status':'running','binary_sha256':sha256(binary),'rejected':{},'accepted':{},
            'command':sys.argv,'harness_sha256':sha256(Path(__file__)),
            'fixture_helper_sha256':sha256(Path(f.__file__)),
            'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'scope':'Patched regtest only; generic TXCOMMIT annex plus fixed allowlist payout policy',
            'annex_public_source':public_block['raw_url'],'annex_public_block':public_block['hash']}
    try:
        key=f.push(f.TXCOMMIT_KEY)
        scripts=[key+b'\xac',key+b'\xad\x51',b'\x00'+key+b'\xba\x51\x9c',
                 key+b'\xac\x91',b'\x00'+key+b'\xba\x00\x9c',b'\x7e\x00',
                 (b'\x76'+key+b'\xad')*8+b'\x75\x51',
                 (b'\x76'+key+b'\xad')*9+b'\x75\x51']
        leaves=[f.Leaf(f.policy_script()),f.Leaf(b'\x51')]+[f.Leaf(s) for s in scripts]
        funding,address,_,base_spk,base_control=fund(f,node,leaves,report)
        policy=leaves[0]
        policy_spk,control=policy.output()
        tx,witness=f.policy_spend(funding,0,0)
        def opening(changed,index=0,recipient=0):
            message=f.sigmsg(changed,index,leaf=f.tapleaf(policy.script))
            return [message[:74],message[74:138],message[170:],f.RECIPIENTS[recipient],
                    f.sha(f.RECIPIENTS[1-recipient]),b'\x01' if recipient else b'',policy.script,control]
        for name,changed in [('version',replace(tx,version=1)),('locktime',replace(tx,locktime=1)),
                             ('sequence',replace(tx,inputs=(replace(tx.inputs[0],sequence=0xfffffffe),)))]:
            rejected(f,node,address,name+'_stale',changed,[witness],report)
            accepted(f,node,address,name+'_recommitted',changed,[opening(changed)],report)
        split=witness.copy()
        split[0],split[1]=witness[0][:-1],witness[0][-1:]+witness[1]
        accepted(f,node,address,'equivalent_prefix_fragmentation',tx,[split],report)
        for name,outputs in [('split_same_total',(f.Output(f.PAYOUT//2,tx.outputs[0].script),)*2),
                             ('zero_output_before',(f.Output(0,b'\x6a'),)+tx.outputs),
                             ('zero_output_after',tx.outputs+(f.Output(0,b'\x6a'),))]:
            changed=replace(tx,outputs=outputs)
            rejected(f,node,address,name,changed,[opening(changed)],report)
        extra=f.Input(bytes.fromhex(funding)[::-1],1,f.AMOUNT,base_spk)
        multiple=replace(tx,inputs=tx.inputs+(extra,))
        base_stack=[leaves[1].script,leaves[1].output()[1]]
        rejected(f,node,address,'added_input_stale',multiple,[witness,base_stack],report)
        accepted(f,node,address,'added_input_recommitted',multiple,[opening(multiple),base_stack],report)
        swapped=replace(multiple,inputs=tuple(reversed(multiple.inputs)))
        rejected(f,node,address,'input_index_stale',swapped,[base_stack,opening(multiple)],report)
        paid=accepted(f,node,address,'input_index_recommitted',swapped,[base_stack,opening(swapped,1)],report,True)
        for offset,leaf in enumerate(leaves[2:5],2):
            spk,ctl=leaf.output()
            current=f.Tx((f.Input(bytes.fromhex(funding)[::-1],offset,f.AMOUNT,spk),),tx.outputs)
            candidate=f.sighash(current,0,leaf=f.tapleaf(leaf.script),annex=annex)
            stack=[candidate,leaf.script,ctl,annex]
            wrong=annex[:-1]+bytes([annex[-1]^1])
            rejected(f,node,address,f'opcode_{offset}_annex_mutation',current,
                     [[candidate,leaf.script,ctl,wrong]],report)
            for size in (0,1,31,33,64,65):
                rejected(f,node,address,f'opcode_{offset}_candidate_size_{size}',current,
                         [[bytes(size),leaf.script,ctl,annex]],report)
            mismatch=bytes([candidate[0]^1])+candidate[1:]
            rejected(f,node,address,f'opcode_{offset}_digest_mismatch',current,
                     [[mismatch,leaf.script,ctl,annex]],report)
            accepted(f,node,address,f'opcode_{offset}_public_annex',current,[stack],report,True)
        for offset,leaf in [(5,leaves[5]),(6,leaves[6])]:
            spk,ctl=leaf.output()
            current=f.Tx((f.Input(bytes.fromhex(funding)[::-1],offset,f.AMOUNT,spk),),tx.outputs)
            candidate=f.sighash(current,0,leaf=f.tapleaf(leaf.script))
            wrong=bytes([candidate[0]^1])+candidate[1:]
            rejected(f,node,address,f'opcode_{offset}_mismatch_cannot_invert',current,
                     [[wrong,leaf.script,ctl]],report)
            accepted(f,node,address,f'opcode_{offset}_empty_false_can_invert',current,
                     [[b'',leaf.script,ctl]],report,True)
        leaf=leaves[7]
        spk,ctl=leaf.output()
        current=f.Tx((f.Input(bytes.fromhex(funding)[::-1],7,f.AMOUNT,spk),),tx.outputs)
        rejected(f,node,address,'cat_active_stack_underflow',current,[[leaf.script,ctl]],report)
        for offset,checks in [(8,8),(9,9)]:
            leaf=leaves[offset]
            spk,ctl=leaf.output()
            current=f.Tx((f.Input(bytes.fromhex(funding)[::-1],offset,f.AMOUNT,spk),),tx.outputs)
            candidate=f.sighash(current,0,leaf=f.tapleaf(leaf.script))
            stack=[candidate,leaf.script,ctl]
            serialized=f.compact(len(stack))+b''.join(f.variable(x) for x in stack)
            budget=50+len(serialized)
            require((budget>=checks*50)==(checks==8),'independent signature budget calculation differs')
            report.setdefault('signature_budget',[]).append({'checks':checks,'required':checks*50,'available':budget})
            if checks==8:
                accepted(f,node,address,'eight_checks_within_budget',current,[stack],report,True)
            else:
                rejected(f,node,address,'ninth_check_exceeds_budget',current,[stack],report)
        alternate,alternative_stack=f.policy_spend(funding,0,1)
        raw,_=alternate.serialize([alternative_stack])
        def spent(name):
            dry=node.rpc('testmempoolaccept',[[raw]])[0]
            require(dry['allowed'] is False and dry['reject-reason']=='missing-inputs',name)
            try:
                node.rpc('sendrawtransaction',[raw])
            except f.RpcError as error:
                require(error.error['code']==-25,name+' unexpected error')
                report[name]={'dry_run':dry,'admission':error.error,'raw':raw}
            else:
                raise ValueError(name+' admitted spent input')
        spent('replay_before_restart')
        height=node.rpc('getblockcount')
        node.stop()
        require(node.start()['blocks']==height,'restart lost height')
        spent('replay_after_restart')
        require(node.rpc('gettxout',[funding,0]) is None,'restart restored spent reserve')
        payout=node.rpc('gettxout',[paid['txid'],0])
        require(payout is not None and f.satoshis(payout['value'])==f.PAYOUT,'restart payout differs')
        require(node.rpc('gettxout',[funding,7]) is not None,'restart lost unused CAT reserve')
        require(node.rpc('getrawmempool')==[],'unexpected mempool residue')
        report.update(status='passed',restart_preserved_outputs=True,final_height=height,
                      rejection_count=len(report['rejected']),positive_count=len(report['accepted']),
                      confirmed_count=sum('block' in x for x in report['accepted'].values()),
                      peer_count=node.rpc('getconnectioncount'))
        require(report['peer_count']==0,'unexpected patched peer')
    except BaseException as error:
        report.update(status='failed',error=f'{type(error).__name__}: {error}')
        raise
    finally:
        finish(node,directory,output,report)
    return report

def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM,interrupted)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--core',type=Path)
    parser.add_argument('--public-report',type=Path)
    args=parser.parse_args()
    require(args.binary or args.core,'a node binary is required')
    args.output.mkdir(parents=True,exist_ok=False)
    f=load_fixture(args.source)
    if args.core:
        result=stock(f,args.core,args.output/'stock')
        print('stock:',result['status'])
    if args.binary:
        require(args.public_report is not None,'verified public fixtures required')
        result=patched(f,args.binary,args.output/'patched',args.public_report)
        print('patched:',result['status'],result['rejection_count'],'block rejections',
              result['positive_count'],'positive cases',result['confirmed_count'],'confirmed')

if __name__=='__main__':
    main()
