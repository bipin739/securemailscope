"""Paginated, escaped PDF export of packet evidence and assessment limits."""
from io import BytesIO
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether


def export_pdf(investigation, report):
    out=BytesIO();styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Meta',fontName='Helvetica',fontSize=8,leading=12,textColor=colors.HexColor('#526779'),spaceAfter=8,wordWrap='CJK'))
    styles['Normal'].fontSize=9;styles['Normal'].leading=14;styles['Normal'].spaceAfter=8
    styles['Heading1'].fontSize=24;styles['Heading1'].leading=30;styles['Heading1'].textColor=colors.HexColor('#153a35')
    styles['Heading2'].fontSize=13;styles['Heading2'].leading=18;styles['Heading2'].spaceBefore=17;styles['Heading2'].spaceAfter=10
    def p(text,style='Normal'):
        # Built-in Helvetica does not support arbitrary Unicode; preserve readable equivalents.
        text=str(text).replace('→',' -> ').replace('•',' / ').replace('—','-').replace('–','-')
        return Paragraph(escape(text),styles[style])
    provenance='Illustrative demo' if investigation.is_simulated else 'Synthetic lab PCAP' if investigation.capture_origin=='SYNTHETIC_LAB' else 'Uploaded capture (origin unverified)'
    story=[p('SECUREMAILSCOPE / SIH 26159','Meta'),p('Cryptographic posture assessment','Heading1'),p(provenance,'Heading2'),p(investigation.filename),
           p('Capture timestamp: '+investigation.capture_date,'Meta'),p('Source SHA-256: '+str(investigation.sha256_hash or 'Not available for demo'),'Meta'),
           p('Generated: '+report.report_metadata.generated_at,'Meta')]
    cells=[[p('MAIL SESSIONS','Meta'),p('POSTURE','Meta'),p('EVIDENCE GAPS','Meta')],
           [p(investigation.summary.sessions_analyzed),p(report.security_posture.status),p(report.security_posture.coverage_gaps)]]
    table=Table(cells,colWidths=[165,185,165]);table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#eff5f3')),('BOX',(0,0),(-1,-1),.5,colors.HexColor('#cddbd7')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),8)]));story +=[table,Spacer(1,12),p(report.executive_summary.full_text)]
    story += [p('Prioritized security findings','Heading2')]
    ranked=sorted(report.deterministic_findings,key=lambda f:(f.status not in ('FAIL','WARN'),['CRITICAL','HIGH','MEDIUM','LOW','INFO'].index(f.severity)))
    for f in ranked:
        story.append(KeepTogether([p(f'{f.severity} / {f.status} / {f.rule_id}','Meta'),p(f.title,'Heading2')]))
        story += [p(f.plain_explanation),p('Evidence: '+f.evidence,'Meta'),p('Recommendation: '+f.recommendation),p('References: '+', '.join(f.references),'Meta')]
        if f.remediation:
            story.append(p('[RULE] Recommended fix','Heading2'))
            story.extend(p(str(i+1)+'. '+step) for i,step in enumerate(f.remediation.steps))
            if f.remediation.snippet:
                snippet=f.remediation.snippet
                story.extend([p(snippet.software+' / '+snippet.warning,'Meta'),p(snippet.scope,'Meta')])
                story.extend(p(line,'Meta') for line in snippet.config.splitlines())
    story += [p('Session evidence and certificates','Heading2')]
    for c in investigation.connections:
        story.append(p(f'{c.session_id}: {c.source_label} -> {c.target_label}','Heading2'))
        story.append(p(f'{c.protocol} / {c.transport_mode} / {c.tls_version} / {c.cipher_suite}'))
        story.append(p(f'ServerHello frame: {c.server_hello_frame or "not captured"}. Packets: {c.evidence.packet_count}. STARTTLS requested: {c.starttls_requested}; accepted: {c.starttls_accepted}; ServerHello after upgrade: {c.starttls_used}.','Meta'))
        q=c.quantum_readiness
        if q:
            story.extend([p(f"INFO / [{q['type']}] {q['label']}"),p(f"Group: {q.get('group_name') or q.get('group') or 'UNKNOWN'}. {q['detail']}",'Meta')])
        for cert in c.certificates:
            story += [p(cert['subject']),p(f"Issuer: {cert['issuer']}. Key: {cert['public_key_algorithm']} {cert['public_key_bits'] or ''}. Signature hash: {cert['signature_hash']}.",'Meta'),p(f"Validity: {cert['not_before']} to {cert['not_after']}. Capture frame: {cert['frame']}.",'Meta'),p(cert['chain_detail']),p('Certificate SHA-256: '+cert['sha256'],'Meta')]
    story += [p('AI-assisted prioritization','Heading2'),p(report.ai_assisted_prioritization.summary_explanation),p(report.ai_assisted_prioritization.disclaimer,'Meta'),p('Assessment boundaries','Heading2')]
    story += [p('- '+s) for s in report.limitations]
    story += [p('Evidence integrity','Heading2'),p('Report digest: '+report.evidence_manifest.report_digest,'Meta'),p('Hashes detect changes only when compared with an independently retained reference. They are not digital signatures and do not authenticate the analyst or the capture origin.'),p(report.privacy_statement,'Meta')]
    def page(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(colors.HexColor('#ccd8d5'));canvas.line(40,42,555,42);canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#657b87'));canvas.drawString(40,28,'SecureMailScope | Passive forensic assessment');canvas.drawRightString(555,28,f'Page {doc.page}');canvas.restoreState()
    SimpleDocTemplate(out,pagesize=A4,rightMargin=40,leftMargin=40,topMargin=38,bottomMargin=58,title='SecureMailScope forensic report',author='SecureMailScope').build(story,onFirstPage=page,onLaterPages=page)
    return out.getvalue()
