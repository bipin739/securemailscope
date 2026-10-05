import React from 'react';
import { Investigation } from '../types';
import { SecurityReplay } from '../components/SecurityReplay';
import { HonestyBanner } from '../components/HonestyBanner';

interface ReplayPageProps {
  investigation: Investigation;
  selectedSessionId?: string;
  selectedEventId?: string;
  onNavigateToFinding?: (ruleId: string) => void;
}

export const ReplayPage: React.FC<ReplayPageProps> = ({
  investigation,
  selectedSessionId,
  selectedEventId,
  onNavigateToFinding,
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />
      <SecurityReplay
        investigation={investigation}
        initialSessionId={selectedSessionId}
        initialEventId={selectedEventId}
        onNavigateToFinding={onNavigateToFinding}
      />
    </div>
  );
};
