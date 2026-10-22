"""Regression assertions against real namespaces, kernel rules and applications."""
import json
from pathlib import Path
import subprocess
import sys
import time
from runtime import DEVICES, IntegratedPolicyEngine


def verify(lab):
    from lab import ns, dump
    rows = []
    output = lab.output/'application_checks.json'
    app = Path(__file__).with_name('application_services.py')
    def record(label, expected, observed, evidence):
        row = dict(check=label, expected=expected, observed=observed,
                   passed=expected == observed, evidence=evidence, at_ns=time.time_ns())
        rows.append(row)
        dump(output, rows)
        if not row['passed']:
            raise AssertionError('live regression failed: '+label)
    def check(name, mode, target, expected=True, invalid=False, label=None):
        result = ns(lab.hosts[name]['namespace'], sys.executable, '-B', str(app), mode,
                    target, str(lab.app_dir), 'anonymous' if invalid=='anonymous' else 'invalid' if invalid else 'valid', timeout=10)
        evidence = json.loads(result.stdout)
        evidence.update(source=name, address=lab.hosts[name]['address'], vlan=lab.hosts[name]['vlan'],
                        resolver=Path(lab.hosts[name]['resolver']).read_text())
        observed = evidence['success']
        if invalid and mode == 'ftp':
            # A timeout or a rejected TCP connection cannot pass an authentication test.
            observed = evidence.get('authenticated') is False and evidence.get('reply_code') == '530'
        if invalid and mode == 'https':
            record('untrusted TLS certificate rejected', 'SSLCertVerificationError', evidence.get('error_type'), evidence)
        record(label or name+' '+mode+' '+target+(' bad password' if invalid else ''), expected, observed, evidence)
        return evidence
    admin = lab.hosts['PC-ADM1']
    for name in ('PC-STU1','PC-FAC1','PC-RES1'):
        host = lab.hosts[name]
        for source, destination, expected in [('PC-ADM1',host['address'],True),
                                               (name,admin['address'],False)]:
            response = ns(lab.hosts[source]['namespace'],'ping','-c','3','-W','1',destination,check=False)
            record(source+' ICMP exchange '+destination, expected, response.returncode == 0,
                   dict(stdout=response.stdout, stderr=response.stderr, exit_code=response.returncode))
        # Unsolicited echo replies must not bypass the user-to-admin prohibition.
        receiver = "import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.settimeout(1); found=False\ntry:\n while True:\n  p=s.recv(4096)\n  if p[20]==0 and p[24:28]==bytes.fromhex('7a5b0001'): found=True; break\nexcept TimeoutError: pass\nprint(json.dumps(found))"
        proc = subprocess.Popen(['ip','netns','exec',admin['namespace'],sys.executable,'-B','-c',receiver],stdout=subprocess.PIPE,text=True)
        time.sleep(.15)
        sender = "import socket,struct; p=bytes.fromhex('080000007a5b0001')+b'unsolicited'; p+=b'\\0'*(len(p)%2); total=sum(struct.unpack('!%dH'%(len(p)//2),p)); total=(total>>16)+(total&65535); total+=(total>>16); p=p[:2]+struct.pack('!H',~total&65535)+p[4:]; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.sendto(p,('"+host['address']+"',0))"
        ns(admin['namespace'],sys.executable,'-B','-c',sender)
        control = json.loads(proc.communicate(timeout=4)[0])
        record(name+' solicited raw reply receiver control',True,control,{})
        receiver = receiver.replace('7a5b0001','7a5c0001')
        proc = subprocess.Popen(['ip','netns','exec',admin['namespace'],sys.executable,'-B','-c',receiver],stdout=subprocess.PIPE,text=True)
        time.sleep(.15)
        sender = "import socket,struct; p=bytes.fromhex('000000007a5c0001')+b'unsolicited'; p+=b'\\0'*(len(p)%2); total=sum(struct.unpack('!%dH'%(len(p)//2),p)); total=(total>>16)+(total&65535); total+=(total>>16); p=p[:2]+struct.pack('!H',~total&65535)+p[4:]; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.sendto(p,('"+admin['address']+"',0))"
        sent = ns(host['namespace'],sys.executable,'-B','-c',sender)
        received = json.loads(proc.communicate(timeout=4)[0])
        record(name+' unsolicited echo reply blocked',False,received,dict(receiver_received=received))
    check('PC-ADM1','https','srv-research',False,invalid=True)
    for name in ('PC-STU1','PC-FAC1','PC-RES1','PC-ADM1'):
        check(name,'resolve','www.example.com')
        check(name,'http','www.example.com')
        check(name,'https','www.example.com')
        check(name,'https','srv-research',name!='PC-STU1')
        check(name,'https','srv-admin',name=='PC-ADM1')
        permitted = name in ('PC-RES1','PC-ADM1')
        evidence = check(name,'ftp','srv-db',permitted)
        if permitted:
            record(name+' FTP data transfer on supplied port 20',20,evidence.get('data_port'),evidence)
            check(name,'ftp','srv-db',True,invalid=True)
            check(name,'ftp','srv-db',True,invalid='anonymous')
    # Use the actual Member 3 policy interface and verified backend, not direct VLAN mocks.
    engine = IntegratedPolicyEngine(state_db_path=str(lab.output/'application_state.json'),
        events_db_path=str(lab.output/'application_events.json'), ssh_enforcer=lab,
        evidence=lab.output/'application_transitions.jsonl')
    name = 'PC-RES2'
    check(name,'https','srv-research')
    check(name,'ftp','srv-db')
    for state,vlan in [('RESTRICTED',60),('QUARANTINE',70)]:
        engine.enforce_state(name,state,'LIVE_APPLICATION_REGRESSION')
        info = DEVICES[name]
        record('actual '+state+' VLAN',vlan,lab.verify_vlan(info['switch_ip'],info['port']),
               engine.state_manager.get_state(name))
        record(state+' DHCP resolver', '192.168.50.13',
               Path(lab.hosts[name]['resolver']).read_text().splitlines()[0].split()[1], {})
        check(name,'resolve','srv-remediate',vlan==60)
        check(name,'http','srv-remediate',vlan==60)
        check(name,'resolve','www.example.com',False)
        # IP-based denials prove firewall isolation independently of DNS failure.
        check(name,'https','192.168.50.10',False)
        check(name,'ftp','192.168.50.11',False)
    record('verified manual application recovery',True,engine.manual_clear(name),{})
    record('recovery DNS option restored','203.0.113.2',
           Path(lab.hosts[name]['resolver']).read_text().splitlines()[0].split()[1],{})
    check(name,'resolve','www.example.com')
    check(name,'http','www.example.com')
    check(name,'https','srv-research')
    check(name,'ftp','srv-db')
    check(name,'https','srv-admin',False)
    dump(lab.output/'application_summary.json',dict(checks=len(rows),passed=sum(r['passed'] for r in rows),
         evidence='application_checks.json',scope='real Linux namespaces, DHCP, nftables, TLS and FTP'))
