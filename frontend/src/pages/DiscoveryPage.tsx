import React from 'react';
import { Investigation } from '../types';
import { ClientDiscovery } from '../components/ClientDiscovery';
import { HonestyBanner } from '../components/HonestyBanner';

interface DiscoveryPageProps {
  investigation: Investigation;
  onNavigateToFindings: (findingIds: string[]) => void;
  onNavigateToReplay: (sessionId: string) => void;
  onNavigateToSimulator: (clientId: string) => void;
}

export const DiscoveryPage: React.FC<DiscoveryPageProps> = ({
  investigation,
  onNavigateToFindings,
  onNavigateToReplay,
  onNavigateToSimulator,
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />
      <ClientDiscovery
        investigation={investigation}
        onNavigateToFindings={onNavigateToFindings}
        onNavigateToReplay={onNavigateToReplay}
        onNavigateToSimulator={onNavigateToSimulator}
      />
    </div>
  );
};
