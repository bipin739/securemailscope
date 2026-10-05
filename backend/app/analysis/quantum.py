"""INFO-only ServerHello key-share observations; never a failing posture check.

Group names/codes verified against the installed Wireshark 4.6.9 value table.
This bounded allowlist does not guess the meaning of unknown/private identifiers.
"""
HYBRID = {0x11eb:'SecP256r1MLKEM768', 0x11ec:'X25519MLKEM768', 0x11ed:'SecP384r1MLKEM1024',
          0x6399:'X25519Kyber768Draft00 (obsolete draft)', 0x639a:'SecP256r1Kyber768Draft00 (obsolete draft)'}
CLASSICAL = {0x17:'secp256r1',0x18:'secp384r1',0x19:'secp521r1',0x1d:'x25519',0x1e:'x448',
             0x100:'ffdhe2048',0x101:'ffdhe3072',0x102:'ffdhe4096',0x103:'ffdhe6144',0x104:'ffdhe8192'}


def quantum_indicator(version, group, frame=None):
    try: number=int(str(group),16 if str(group).startswith('0x') else 10)
    except (ValueError,TypeError): number=None
    base=dict(severity='INFO',group=group,frame=frame,applicability='TLS 1.3 ServerHello only')
    if version=='TLS 1.3' and number in HYBRID:
        return dict(**base,type='OBSERVED',classification='PQ_HYBRID_OBSERVED',group_name=HYBRID[number],
                    label='PQ hybrid observed',detail='ServerHello selected a recognized hybrid group. This does not prove handshake completion, PQ authentication, or overall quantum security.')
    if version=='TLS 1.3' and number in CLASSICAL:
        return dict(**base,type='OBSERVED',classification='CLASSICAL_OBSERVED',group_name=CLASSICAL[number],
                    label='Classical key exchange observed',detail='May be exposed to harvest-now-decrypt-later; this is an observation, not a vulnerability.')
    return dict(**base,type='COVERAGE_GAP',classification='UNKNOWN',group_name=None,label='Quantum readiness: UNKNOWN',
                detail='A recognized TLS 1.3 ServerHello key-share group is not visible. No readiness conclusion or failing check is produced.')
