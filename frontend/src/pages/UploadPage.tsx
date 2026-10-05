import React from 'react';
import { UploadCapture } from '../components/UploadCapture';
import { HonestyBanner } from '../components/HonestyBanner';
import { Investigation } from '../types';
import { LabCaptures } from '../components/LabCaptures';

interface UploadPageProps {
  onViewDemo: () => void;
  investigation: Investigation | null;
  onInvestigationLoaded: (investigation: Investigation) => void;
}

export const UploadPage: React.FC<UploadPageProps> = ({ 
  onViewDemo, 
  investigation, 
  onInvestigationLoaded 
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />
      <LabCaptures onLoaded={onInvestigationLoaded}/>
      <UploadCapture
        onViewDemo={onViewDemo}
        onInvestigationLoaded={onInvestigationLoaded}
      />
    </div>
  );
};
