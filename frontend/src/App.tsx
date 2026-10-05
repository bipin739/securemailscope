import React, { useState, useEffect } from 'react';


import { 


  ActiveTab, 


  Investigation, 


  HealthResponse, 


  NetworkConnection, 


  SecurityFinding 


} from './types';


import { fetchHealth, fetchDemoInvestigation } from './services/api';


import { getCumulativeAnalytics, recordAnalyzedCapture, CumulativeAnalytics } from './services/analytics';


import { Header } from './components/WorkspaceHeader';


import { ConnectionDetailDrawer } from './components/ConnectionDetailDrawer';


import { OverviewPage } from './pages/Dashboard';


import { FindingsPage } from './pages/FindingsPage';


import { DiscoveryPage } from './pages/DiscoveryPage';


import { SimulatorPage } from './pages/SimulatorPage';


import { ReplayPage } from './pages/ReplayPage';


import { ReportPage } from './pages/ReportPage';


import { UploadPage } from './pages/UploadPage';


import { RefreshCw, AlertCircle, Shield } from 'lucide-react';





export const App: React.FC = () => {


  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');


  const [investigation, setInvestigation] = useState<Investigation | null>(null);


  const [health, setHealth] = useState<HealthResponse | null>(null);


  const [loading, setLoading] = useState<boolean>(true);


  const [healthLoading, setHealthLoading] = useState<boolean>(false);


  const [error, setError] = useState<string | null>(null);


  const [selectedConnection, setSelectedConnection] = useState<NetworkConnection | null>(null);


  const [cumulativeAnalytics, setCumulativeAnalytics] = useState<CumulativeAnalytics>(() => getCumulativeAnalytics());


  const [selectedSimulatorPolicies, setSelectedSimulatorPolicies] = useState<string[]>([


    'SMS-POLICY-TLS12',


    'SMS-POLICY-NO-WEAK-CIPHER'


  ]);


  const [selectedReplaySessionId, setSelectedReplaySessionId] = useState<string>('');


  const [selectedReplayEventId, setSelectedReplayEventId] = useState<string>('');





  const loadData = async () => {


    setLoading(true);


    setError(null);


    try {


      // Check health


      try {


        setHealthLoading(true);


        const healthData = await fetchHealth();


        setHealth(healthData);


      } catch (hErr) {


        console.warn('Backend health check error:', hErr);


        setHealth(null);


      } finally {


        setHealthLoading(false);


      }





      // Fetch demo investigation


      const invData = await fetchDemoInvestigation();


      setInvestigation(invData);


      setCumulativeAnalytics(getCumulativeAnalytics());


    } catch (err: unknown) {


      console.error('Failed to load investigation:', err);


      const errorMessage = err instanceof Error ? err.message : 'Failed to connect to SecureMailScope backend API.';


      setError(errorMessage);


    } finally {


      setLoading(false);


    }


  };





  const handleLoadDemo = async () => {


    try {


      setLoading(true);


      const demoData = await fetchDemoInvestigation();


      setInvestigation(demoData);


      setSelectedConnection(null);


      setSelectedReplaySessionId('');


      setSelectedReplayEventId('');


      setSelectedSimulatorPolicies(['SMS-POLICY-TLS12', 'SMS-POLICY-NO-WEAK-CIPHER']);


      setCumulativeAnalytics(getCumulativeAnalytics());


      setActiveTab('overview');


    } catch (err: unknown) {


      setError(err instanceof Error ? err.message : 'Could not load demo');


    } finally {


      setLoading(false);


    }


  };





  const handleInvestigationLoaded = (newInv: Investigation) => {


    // Record into persistent cumulative analytics store (increments only if unique real capture)


    const { analytics } = recordAnalyzedCapture(newInv);


    setCumulativeAnalytics(analytics);





    setInvestigation(newInv);


    setSelectedConnection(null);


    setSelectedReplaySessionId('');


    setSelectedReplayEventId('');


    setSelectedSimulatorPolicies(['SMS-POLICY-TLS12', 'SMS-POLICY-NO-WEAK-CIPHER']);


    setActiveTab('overview');


    window.scrollTo({ top: 0, behavior: 'smooth' });


  };





  const handleNavigateToSimulator = (policyId: string) => {


    setSelectedSimulatorPolicies([policyId]);


    setActiveTab('simulator');


    window.scrollTo({ top: 0, behavior: 'smooth' });


  };





  const handleNavigateToReplay = (ruleIdOrEventId: string, sessionId?: string) => {


    if (sessionId) setSelectedReplaySessionId(sessionId);


    setSelectedReplayEventId(ruleIdOrEventId);


    setActiveTab('replay');


    window.scrollTo({ top: 0, behavior: 'smooth' });


  };





  useEffect(() => {


    loadData();


  }, []);





  const handleSelectConnection = (conn: NetworkConnection) => {


    setSelectedConnection(conn);


  };





  const handleSelectFinding = (finding: SecurityFinding) => {


    if (investigation && finding.affected_connection_id) {


      const conn = investigation.connections.find((c) => c.id === finding.affected_connection_id);


      if (conn) {


        setSelectedConnection(conn);


        return;


      }


    }


    if (investigation && investigation.connections.length > 0) {


      setSelectedConnection(investigation.connections[0]);


    }


  };





  const handleSelectHop = (connectionId: string) => {


    if (investigation) {


      const conn = investigation.connections.find((c) => c.id === connectionId);


      if (conn) setSelectedConnection(conn);


    }


  };





  const isRealCapture = investigation && (!investigation.is_simulated || investigation.data_source === 'REAL_CAPTURE');





  return (


    <div className="min-h-screen bg-[#0b1016] text-slate-100 flex flex-col selection:bg-sky-500/30 selection:text-sky-200">


      {/* Header Bar */}


      <Header


        activeTab={activeTab}


        onTabChange={(tab) => {


          setActiveTab(tab);


          window.scrollTo({ top: 0, behavior: 'smooth' });


        }}


        health={health}


        healthLoading={healthLoading}


        onRefresh={async () => { setHealthLoading(true); try { setHealth(await fetchHealth()); } catch { setHealth(null); } finally { setHealthLoading(false); } }}


        investigation={investigation}


        onLoadDemo={handleLoadDemo}


      />





      {/* Main Container */}


      <main className="workspace-main">


        {loading ? (


          <div className="py-28 flex flex-col items-center justify-center space-y-4">


            <div className="relative">


              <div className="w-12 h-12 rounded-full border-2 border-sky-500/20 border-t-sky-400 animate-spin" />


              <Shield className="w-5 h-5 text-sky-400 absolute inset-0 m-auto" />


            </div>


            <div className="text-center space-y-1">


              <span className="text-sm font-semibold text-slate-200">


                Connecting to SecureMailScope Engine...


              </span>


              <p className="text-xs text-slate-500">


                Fetching transport security topology from backend API


              </p>


            </div>


          </div>


        ) : error ? (


          <div className="py-16 max-w-xl mx-auto text-center space-y-4">


            <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mx-auto">


              <AlertCircle className="w-6 h-6" />


            </div>


            <div className="space-y-1">


              <h3 className="text-base font-bold text-white">Backend Connection Error</h3>


              <p className="text-xs text-slate-400 leading-relaxed font-mono">


                {error}


              </p>


            </div>


            <div className="pt-2">


              <button


                onClick={loadData}


                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-bold transition"


              >


                <RefreshCw className="w-3.5 h-3.5" />


                <span>Retry Connection</span>


              </button>


            </div>


            <div className="text-xs text-slate-500 pt-4 border-t border-slate-800">


              Ensure backend is running: <code className="text-sky-400 font-mono">uvicorn app.main:app --port 8000</code>


            </div>


          </div>


        ) : investigation ? (


          <>


            {activeTab === 'overview' && (


              <OverviewPage


                investigation={investigation}


                selectedConnection={selectedConnection}


                onSelectConnection={handleSelectConnection}


                onSelectFinding={handleSelectFinding}


                onNavigateToSimulator={handleNavigateToSimulator}


                onNavigateToReplay={handleNavigateToReplay}


                cumulativeAnalytics={cumulativeAnalytics}


                onNavigate={setActiveTab}


              />


            )}





            {activeTab === 'findings' && (


              <FindingsPage


                investigation={investigation}


                onSelectFinding={handleSelectFinding}


                onNavigateToSimulator={handleNavigateToSimulator}


                onNavigateToReplay={handleNavigateToReplay}


              />


            )}





            {activeTab === 'discovery' && (


              <DiscoveryPage


                investigation={investigation}


                onNavigateToFindings={() => {


                  setActiveTab('findings');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


                onNavigateToReplay={(sessionId) => {


                  if (sessionId) setSelectedReplaySessionId(sessionId);


                  setActiveTab('replay');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


                onNavigateToSimulator={() => {


                  setActiveTab('simulator');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


              />


            )}





            {activeTab === 'replay' && (


              <ReplayPage


                investigation={investigation}


                selectedSessionId={selectedReplaySessionId}


                selectedEventId={selectedReplayEventId}


                onNavigateToFinding={() => {


                  setActiveTab('findings');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


              />


            )}





            {activeTab === 'simulator' && (


              <SimulatorPage


                investigation={investigation}


                initialSelectedPolicies={selectedSimulatorPolicies}


                onSelectPolicyFromBridge={handleNavigateToSimulator}


              />


            )}





            {activeTab === 'report' && (


              <ReportPage


                investigation={investigation}


                onNavigateToSimulator={handleNavigateToSimulator}


                onNavigateToReplay={handleNavigateToReplay}


                onNavigateToFindings={() => {


                  setActiveTab('findings');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


                onNavigateToDiscovery={() => {


                  setActiveTab('discovery');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


                onNavigateToUpload={() => {


                  setActiveTab('upload');


                  window.scrollTo({ top: 0, behavior: 'smooth' });


                }}


              />


            )}





            {activeTab === 'upload' && (


              <UploadPage


                onViewDemo={handleLoadDemo}


                investigation={investigation}


                onInvestigationLoaded={handleInvestigationLoaded}


              />


            )}


          </>


        ) : null}


      </main>





      {/* Side Drawer */}


      {investigation && (


        <ConnectionDetailDrawer


          connection={selectedConnection}


          nodes={investigation.nodes}


          allConnections={investigation.connections}


          findings={investigation.findings}


          onSelectHop={handleSelectHop}


          onClose={() => setSelectedConnection(null)}


          isSimulated={investigation.is_simulated}


          onNavigateToSimulator={handleNavigateToSimulator}


        />


      )}





      {/* Footer */}


      <footer className="workspace-footer"><span>SecureMailScope · SIH 26159</span><span>Offline forensic workspace · {isRealCapture ? 'Packet-derived analysis' : 'Illustrative demo'}</span></footer>


    </div>


  );


};


export default App;


