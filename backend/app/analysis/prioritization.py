"""Explainable ordering; not a trained or calibrated risk score."""
SEVERITY = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}


def build_fix_first(investigation):
    discovery = investigation.discovery
    assessment = discovery.get('anomaly_assessment') if isinstance(discovery,dict) else getattr(discovery, 'anomaly_assessment', None)
    if isinstance(assessment,dict):
        from app.discovery.models import AnomalyAssessment
        assessment=AnomalyAssessment.model_validate(assessment)
    results = assessment.results if assessment and assessment.status == 'ANALYZED' else []
    # Equal anomaly scores receive equal rank; client IDs never become ML evidence.
    distinct_scores = sorted({r.anomaly_score for r in results}, reverse=True)
    ranks = {r.client_id: distinct_scores.index(r.anomaly_score)+1 for r in results}
    population = len(results)
    session_weight = population + 1
    severity_weight = (len(investigation.connections) + 1) * session_weight
    nodes = {n.id:n.ip_address for n in investigation.nodes}
    connections = {c.id:c for c in investigation.connections}
    groups = {}
    for finding in investigation.findings:
        if finding.status not in ('FAIL', 'WARN'):
            continue
        key = (finding.rule_id, finding.severity)
        row = groups.setdefault(key, dict(type='RULE', rule_id=finding.rule_id, title=finding.title,
            severity=finding.severity, finding_ids=[], connection_ids=set(), client_ids=set()))
        row['finding_ids'].append(finding.id)
        conn = connections.get(finding.affected_connection_id)
        if conn:
            row['connection_ids'].add(conn.id)
            ip = nodes.get(conn.source_node_id)
            if ip: row['client_ids'].add(f'{conn.protocol}:{ip}')
    for row in groups.values():
        row['affected_sessions'] = len(row['connection_ids'])
        row['anomaly_rank'] = min((ranks[c] for c in row['client_ids'] if c in ranks), default=None)
        points = population-row['anomaly_rank']+1 if row['anomaly_rank'] is not None else 0
        row['ordering_points'] = SEVERITY[row['severity']]*severity_weight + row['affected_sessions']*session_weight + points
        row['connection_ids'] = sorted(row['connection_ids'])
        row['client_ids'] = sorted(row['client_ids'])
        row['finding_ids'].sort()
        row['evidence'] = [dict(type='RULE',field='severity',value=row['severity'],source='Deterministic findings'),
                           dict(type='OBSERVED',field='affected_sessions',value=row['affected_sessions'],source='Unique captured TCP sessions'),
                           dict(type='RULE' if row['anomaly_rank'] else 'COVERAGE_GAP',field='anomaly_rank',value=row['anomaly_rank'],source='Within-capture Isolation Forest; tie-breaker only')]
    rows = sorted(groups.values(), key=lambda r:(-r['ordering_points'],r['rule_id']))
    for i,row in enumerate(rows):row['rank']=i+1
    return dict(type='RULE',label='Heuristic prioritisation, not a calibrated risk score',
                weights=dict(severity=severity_weight,affected_sessions=session_weight,anomaly_tiebreak=1),
                severity_values=SEVERITY,anomaly_population=population,
                anomaly_status=assessment.status if assessment else 'UNAVAILABLE',
                formula='severity value × severity weight + affected sessions × session weight + anomaly points (population − rank + 1; zero when unavailable). Weights ensure strict severity, then session-count precedence.',
                rows=rows)
