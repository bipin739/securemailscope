"""Generate synthetic Ethernet/IP/TCP PCAPs with real OpenSSL TLS handshakes.

No sockets, external servers, real credentials, or packet capture privileges required.
TLS bytes are produced by ssl.MemoryBIO; only the legacy regression is hand-built.
"""
from pathlib import Path
import datetime as dt
import hashlib
import json
import socket
import ssl
import struct
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

OUT = Path(__file__).resolve().parents[2] / 'sample-captures'
STAMP = 1791115200  # 2026-10-04 12:00 UTC; validity is assessed at packet time.


def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535


class Capture:
    def __init__(self): self.packets = []
    def packet(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        a,b=socket.inet_aton(src),socket.inet_aton(dst)
        tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,80,flags,65535,0,0)+payload
        check=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp)
        tcp=tcp[:16]+struct.pack('!H',check)+tcp[18:]
        ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),len(self.packets)%65536,0,64,6,0,a,b)
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        self.packets.append(bytes.fromhex('0200000000020200000000010800')+ip+tcp)
    def stream(self, port, exchanges, client=1, split=False, disorder=False):
        a,b=f'192.0.2.{client}','198.51.100.25'; sport=49000+client
        seq=[1000,9000]
        self.packet(a,b,sport,port,seq[0],0,2);seq[0]+=1
        self.packet(b,a,port,sport,seq[1],seq[0],18);seq[1]+=1
        self.packet(a,b,sport,port,seq[0],seq[1],16)
        for direction,payload in exchanges:
            d=0 if direction=='c' else 1
            chunks=[payload[i:i+89] for i in range(0,len(payload),89)] if split else [payload]
            pending=[]
            for chunk in chunks:
                pending.append((seq[d],chunk));seq[d]+=len(chunk)
            if disorder and len(pending)>2: pending[0],pending[1]=pending[1],pending[0]
            for number,chunk in pending:
                self.packet(a if d==0 else b,b if d==0 else a,sport if d==0 else port,port if d==0 else sport,number,seq[1-d],24,chunk)
            self.packet(b if d==0 else a,a if d==0 else b,port if d==0 else sport,sport if d==0 else port,seq[1-d],seq[d],16)
        self.packet(a,b,sport,port,seq[0],seq[1],17)
        self.packet(b,a,port,sport,seq[1],seq[0]+1,17)
    def write(self,name):
        if name.endswith('.pcapng'):
            def block(kind,body):
                body+=b'\0'*(-len(body)%4);size=12+len(body)
                return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
            data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
            for i,p in enumerate(self.packets):
                stamp=STAMP*1000000+i*1000
                data+=block(6,struct.pack('<IIIII',0,stamp>>32,stamp&0xffffffff,len(p),len(p))+p)
            (OUT/name).write_bytes(data)
            return hashlib.sha256(data).hexdigest()
        data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
        for i,p in enumerate(self.packets): data+=struct.pack('<IIII',STAMP+i//1000,(i%1000)*1000,len(p),len(p))+p
        (OUT/name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()


def credentials(folder, expired=False):
    now=dt.datetime(2026,10,4,tzinfo=dt.timezone.utc)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'mail.sih.test')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(26159)
          .not_valid_before(now-dt.timedelta(days=100)).not_valid_after(now+dt.timedelta(days=-1 if expired else 365))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.sih.test')]),critical=False)
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(key,hashes.SHA256()))
    crt=Path(folder)/('expired.pem' if expired else 'server.pem');pk=Path(folder)/('expired.key' if expired else 'server.key')
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM));pk.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return crt,pk


def tls_exchange(cert,key,version):
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(cert,key)
    client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
    for ctx in (server,client):ctx.minimum_version=version;ctx.maximum_version=version
    if version==ssl.TLSVersion.TLSv1_2:
        for ctx in (server,client):ctx.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    ci,co,si,so=(ssl.MemoryBIO() for _ in range(4))
    c=client.wrap_bio(ci,co,server_side=False,server_hostname='mail.sih.test');s=server.wrap_bio(si,so,server_side=True)
    exchanges=[];done=[False,False]
    for _ in range(12):
        for idx,obj,out,incoming,direction in [(0,c,co,si,'c'),(1,s,so,ci,'s')]:
            if not done[idx]:
                try:obj.do_handshake();done[idx]=True
                except ssl.SSLWantReadError:pass
            data=out.read()
            if data:exchanges.append((direction,data));incoming.write(data)
        if all(done):break
    assert all(done),'OpenSSL handshake incomplete'
    c.write(b'EHLO synthetic.sih.test\r\n');payload=co.read();exchanges.append(('c',payload));si.write(payload);s.read()
    return exchanges


def trusted_credentials(folder):
    now=dt.datetime(2026,10,4,tzinfo=dt.timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SIH Synthetic Lab Root - test only')])
    root=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(2615901)
          .not_valid_before(now-dt.timedelta(days=30)).not_valid_after(now+dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False).sign(ca_key,hashes.SHA256()))
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'mail.sih.test')]))
          .issuer_name(ca_name).public_key(key.public_key()).serial_number(2615902)
          .not_valid_before(now-dt.timedelta(days=10)).not_valid_after(now+dt.timedelta(days=100))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.sih.test')]),False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False)
          .sign(ca_key,hashes.SHA256()))
    (OUT/'lab-root-ca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    crt=Path(folder)/'chain.pem';pk=Path(folder)/'chain.key'
    crt.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    pk.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return crt,pk


def legacy_client_hello(version, suites):
    """Hand-built complete ClientHello offer fixture; no completed connection claimed."""
    cipher_bytes=b''.join(struct.pack('!H',v) for v in suites)
    body=struct.pack('!H',version)+bytes(range(32))+b'\x00'+struct.pack('!H',len(cipher_bytes))+cipher_bytes+b'\x01\x00'
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16'+struct.pack('!HH',version,len(handshake))+handshake


def generate():
    OUT.mkdir(parents=True,exist_ok=True);manifest=[]
    def save(name,cap,description,expected):
        sha=cap.write(name);manifest.append(dict(filename=name,sha256=sha,description=description,expected=expected,origin='SYNTHETIC_LAB'))
    smtp=[('s',b'220 mail.sih.test ESMTP\r\n'),('c',b'EHLO synthetic.sih.test\r\n'),('s',b'250-mail.sih.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n')]
    clear=smtp+[('c',b'AUTH PLAIN AHN5bnRoZXRpYwBkdW1teQ==\r\n'),('s',b'235 OK\r\n'),('c',b'QUIT\r\n')]
    cap=Capture();cap.stream(587,clear);save('lab-smtp-cleartext-auth.pcap',cap,'SMTP advertises STARTTLS; client authenticates in cleartext.',dict(protocol='SMTP',tls='None',rules=['SMS-AUTH-001','SMS-TLS-001','SMS-STARTTLS-001']))
    cap=Capture();cap.stream(143,[('s',b'* OK IMAP ready\r\n'),('c',b'a1 LOGIN synthetic dummy\r\n'),('s',b'a1 OK LOGIN done\r\n')]);save('lab-imap-cleartext.pcap',cap,'IMAP LOGIN without encryption.',dict(protocol='IMAP',tls='None',rules=['SMS-AUTH-001']))
    cap=Capture();cap.stream(110,[('s',b'+OK POP3 ready\r\n'),('c',b'USER synthetic\r\n'),('s',b'+OK\r\n'),('c',b'PASS dummy\r\n')]);save('lab-pop3-cleartext.pcap',cap,'POP3 authentication without encryption.',dict(protocol='POP3',tls='None',rules=['SMS-AUTH-001']))
    with tempfile.TemporaryDirectory() as td:
        cert,key=credentials(td);expired,expired_key=credentials(td,True)
        tls12=tls_exchange(cert,key,ssl.TLSVersion.TLSv1_2);tls13=tls_exchange(cert,key,ssl.TLSVersion.TLSv1_3)
        upgrade=smtp+[('c',b'STARTTLS\r\n'),('s',b'220 Ready to start TLS\r\n')]
        cap=Capture();cap.stream(587,upgrade+tls12);save('lab-smtp-starttls-tls12.pcap',cap,'Real OpenSSL TLS 1.2 after SMTP STARTTLS; self-issued test certificate.',dict(protocol='SMTP',tls='TLS 1.2',cipher='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',starttls=True,certificates=1))
        cap=Capture();cap.stream(143,[('s',b'* OK IMAP ready\r\n'),('c',b'a1 STARTTLS\r\n'),('s',b'a1 OK Begin TLS\r\n')]+tls12);save('lab-imap-starttls.pcap',cap,'IMAP STARTTLS followed by real TLS 1.2.',dict(protocol='IMAP',tls='TLS 1.2',starttls=True))
        cap=Capture();cap.stream(110,[('s',b'+OK POP3 ready\r\n'),('c',b'STLS\r\n'),('s',b'+OK Begin TLS\r\n')]+tls12);save('lab-pop3-stls.pcap',cap,'POP3 STLS followed by real TLS 1.2.',dict(protocol='POP3',tls='TLS 1.2',starttls=True))
        ca_cert,ca_key=trusted_credentials(td)
        cap=Capture();cap.stream(465,tls_exchange(ca_cert,ca_key,ssl.TLSVersion.TLSv1_2));save('lab-ca-signed-tls12.pcap',cap,'CA-signed lab leaf; validate explicitly using lab-root-ca.pem. Not a public-trust certificate.',dict(protocol='SMTP',tls='TLS 1.2',certificates=1))
        for port,proto in [(465,'SMTP'),(993,'IMAP'),(995,'POP3')]:
            cap=Capture();cap.stream(port,tls13);save(f'lab-{proto.lower()}-tls13.pcap',cap,'Real OpenSSL TLS 1.3; certificate encrypted and unavailable to passive analysis.',dict(protocol=proto,tls='TLS 1.3',certificates=0))
        cap=Capture();cap.stream(993,tls12,split=True,disorder=True);save('lab-fragmented-out-of-order.pcap',cap,'TLS 1.2 records split into 89-byte segments, delivered out of order.',dict(protocol='IMAP',tls='TLS 1.2',certificates=1))
        cap=Capture();cap.stream(465,tls_exchange(expired,expired_key,ssl.TLSVersion.TLSv1_2));save('lab-expired-certificate.pcap',cap,'TLS 1.2 with a certificate expired before the capture timestamp.',dict(protocol='SMTP',tls='TLS 1.2',rules=['SMS-CERT-001'],certificate_issue='Expired at capture time'))
        cap=Capture();cap.stream(465,[tls13[0]]);save('lab-clienthello-only.pcap',cap,'Only ClientHello present; negotiated parameters must remain unknown.',dict(protocol='SMTP',tls='UNKNOWN',forbidden_rules=['SMS-TLSVER-002','SMS-TLSVER-001','SMS-TLS-001']))
        cap=Capture();cap.stream(465,[tls13[-1]]);save('lab-midstream-encrypted.pcap',cap,'Encrypted application data without the handshake.',dict(protocol='SMTP',tls='UNKNOWN',forbidden_rules=['SMS-TLS-001','SMS-TLSVER-002']))
        cap=Capture();cap.stream(587,smtp+[('c',b'STARTTLS\r\n'),('s',b'454 TLS not available\r\n')]);save('lab-starttls-rejected.pcap',cap,'STARTTLS requested but rejected; must not count as a completed upgrade.',dict(protocol='SMTP',tls='UNKNOWN',starttls=False))
        # Manually specified ServerHello: selected TLS 1.0 and static RSA/3DES.
        hello=b'\x03\x01'+bytes(range(32))+b'\x00\x00\x0a\x00'
        handshake=b'\x02'+len(hello).to_bytes(3,'big')+hello
        legacy=b'\x16\x03\x01'+len(handshake).to_bytes(2,'big')+handshake
        cap=Capture();cap.stream(465,[tls12[0],('s',legacy)]);save('lab-legacy-tls10-3des.pcap',cap,'Hand-built legacy ServerHello regression fixture; not a completed TLS connection.',dict(protocol='SMTP',tls='TLS 1.0',cipher='TLS_RSA_WITH_3DES_EDE_CBC_SHA',rules=['SMS-TLSVER-001','SMS-CIPHER-001']))
        cap=Capture()
        for i in range(1,7):cap.stream([465,993,995][i%3],tls13,client=i)
        cap.stream(587,clear,client=7);cap.stream(465,[tls12[0],('s',legacy)],client=8)
        save('lab-mixed-fleet.pcap',cap,'Eight synthetic clients: six modern TLS, one plaintext AUTH, one legacy TLS. Exercises AI outlier ranking.',dict(sessions=8,protocols=['SMTP','IMAP','POP3'],rules=['SMS-AUTH-001','SMS-CIPHER-001']))
        save('lab-mixed-fleet.pcapng',cap,'The same synthetic fleet encoded as PCAPNG.',dict(sessions=8,protocols=['SMTP','IMAP','POP3'],rules=['SMS-AUTH-001','SMS-CIPHER-001']))
        cap=Capture()
        cap.stream(465,tls13,client=21);cap.stream(993,tls12,client=22)
        cap.stream(465,[('c',legacy_client_hello(0x0301,[0x002f])),('s',legacy[:-3]+b'\x00\x2f\x00')],client=23)
        # TLS 1.2 offered, but only 3DES; independent cipher-policy failure.
        selected12=legacy[:1]+b'\x03\x03'+legacy[3:9]+b'\x03\x03'+legacy[11:]
        cap.stream(465,[('c',legacy_client_hello(0x0303,[0x000a])),('s',selected12)],client=24)
        cap.stream(465,[tls13[-1]],client=25)
        save('lab-legacy-clients-offer.pcap',cap,'Five synthetic clients: two modern, TLS 1.0-only offer, 3DES-only offer, and missing ClientHello. Legacy records are hand-built negotiation fixtures, not completed sessions.',dict(sessions=5,simulation_counts=dict(COMPATIBLE=2,WOULD_BREAK=2,UNKNOWN=1)))
    cap=Capture();cap.stream(443,[('c',b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')]);save('lab-no-mail.pcap',cap,'Non-mail HTTP traffic; must yield zero email sessions.',dict(sessions=0))
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2))
    print(f'Generated {len(manifest)} capture fixtures in {OUT}')


if __name__=='__main__':generate()
