import React from 'react';
import { Investigation } from '../types';
import { HardeningSimulator } from '../components/HardeningSimulator';
import { HonestyBanner } from '../components/HonestyBanner';

interface SimulatorPageProps {
  investigation: Investigation;
  initialSelectedPolicies?: string[];
  onSelectPolicyFromBridge?: (policyId: string) => void;
}

export const SimulatorPage: React.FC<SimulatorPageProps> = ({
  investigation,
  initialSelectedPolicies,
  onSelectPolicyFromBridge,
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />
      <HardeningSimulator
        investigation={investigation}
        initialSelectedPolicies={initialSelectedPolicies}
        onSelectPolicyFromBridge={onSelectPolicyFromBridge}
      />
    </div>
  );
};
