import React from 'react';
import { Investigation, NetworkConnection, SecurityFinding } from '../types';
import { HonestyBanner } from '../components/HonestyBanner';
import { SummaryCards } from '../components/SummaryCards';
import { MailSecurityJourney } from '../components/MailSecurityJourney';
import { FindingsTable } from '../components/FindingsTable';
import { CumulativeAnalytics } from '../services/analytics';

interface OverviewPageProps {
  investigation: Investigation;
  selectedConnection: NetworkConnection | null;
  onSelectConnection: (connection: NetworkConnection) => void;
  onSelectFinding: (finding: SecurityFinding) => void;
  onNavigateToSimulator?: (policyId: string) => void;
  onNavigateToReplay?: (ruleId: string) => void;
  cumulativeAnalytics: CumulativeAnalytics;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  investigation,
  selectedConnection,
  onSelectConnection,
  onSelectFinding,
  onNavigateToSimulator,
  onNavigateToReplay,
  cumulativeAnalytics,
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />

      <SummaryCards
        summary={investigation.summary}
        securityPosture={investigation.security_posture}
        filename={investigation.filename}
        captureDate={investigation.capture_date}
        sha256Short={investigation.sha256_short}
        isSimulated={investigation.is_simulated}
        cumulativeAnalytics={cumulativeAnalytics}
      />

      {/* End-to-End Hop Topology */}
      <MailSecurityJourney
        nodes={investigation.nodes}
        connections={investigation.connections}
        selectedConnectionId={selectedConnection?.id || null}
        onSelectConnection={onSelectConnection}
      />

      {/* Findings Section */}
      <FindingsTable
        findings={investigation.findings}
        onSelectFinding={onSelectFinding}
        onNavigateToSimulator={onNavigateToSimulator}
        onNavigateToReplay={onNavigateToReplay}
      />
    </div>
  );
};
