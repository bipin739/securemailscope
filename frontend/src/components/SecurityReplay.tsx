import React, { useState, useEffect, useRef } from 'react';
import {
  Investigation,
  SessionReplay,
  SecurityEvent,
  EventSecurityState,
} from '../types';
import {
  Play,
  Pause,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
  Shield,
  AlertTriangle,
  AlertOctagon,
  ArrowRight,
  ArrowLeft,
  Lock,
  Unlock,
  CheckCircle,
  HelpCircle,
  Clock,
  Terminal,
  Server,
  Laptop,
  Flame,
  Info,
} from 'lucide-react';

interface SecurityReplayProps {
  investigation: Investigation;
  initialSessionId?: string;
  initialEventId?: string;
  onNavigateToFinding?: (ruleId: string) => void;
}

export const SecurityReplay: React.FC<SecurityReplayProps> = ({
  investigation,
  initialSessionId,
  initialEventId,
  onNavigateToFinding,
}) => {
  const replays: SessionReplay[] = investigation.replays || [];

  // Active session selection
  const [selectedSessionId, setSelectedSessionId] = useState<string>(() => {
    if (initialSessionId && replays.some((r) => r.session_id === initialSessionId)) {
      return initialSessionId;
    }
    return replays[0]?.session_id || '';
  });

  const activeReplay = replays.find((r) => r.session_id === selectedSessionId) || replays[0];
  const events = activeReplay?.events || [];

  // Active event index in playback
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1.0);

  // Sync when initialSessionId or initialEventId changes
  useEffect(() => {
    if (initialSessionId && replays.some((r) => r.session_id === initialSessionId)) {
      setSelectedSessionId(initialSessionId);
    }
  }, [initialSessionId, replays]);

  useEffect(() => {
    if (initialEventId && events.length > 0) {
      const idx = events.findIndex((e) => e.event_id === initialEventId || e.related_rule_ids.includes(initialEventId));
      if (idx !== -1) {
        setCurrentStepIndex(idx);
      }
    }
  }, [initialEventId, events]);

  // Keep index in bounds if session changes
  useEffect(() => {
    setCurrentStepIndex(0);
    setIsPlaying(false);
  }, [selectedSessionId]);

  // Playback timer
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (isPlaying) {
      const stepDuration = 1200 / playbackSpeed;
      timerRef.current = setTimeout(() => {
        setCurrentStepIndex((prev) => {
          if (prev >= events.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, stepDuration);
    } else if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isPlaying, currentStepIndex, events.length, playbackSpeed]);

  const handlePlayPause = () => {
    if (currentStepIndex >= events.length - 1) {
      setCurrentStepIndex(0);
    }
    setIsPlaying(!isPlaying);
  };

  const handleRestart = () => {
    setIsPlaying(false);
    setCurrentStepIndex(0);
  };

  const handlePrev = () => {
    setIsPlaying(false);
    setCurrentStepIndex((prev) => Math.max(0, prev - 1));
  };

  const handleNext = () => {
    setIsPlaying(false);
    setCurrentStepIndex((prev) => Math.min(events.length - 1, prev + 1));
  };

  const currentEvent: SecurityEvent | undefined = events[currentStepIndex];

  const getSecurityStateBadge = (state: EventSecurityState) => {
    switch (state) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-bold bg-rose-500/15 text-rose-300 border border-rose-500/40">
            <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
            <span>CRITICAL</span>
          </span>
        );
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-bold bg-amber-500/15 text-amber-300 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>WARNING</span>
          </span>
        );
      case 'SECURE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
            <span>SECURE</span>
          </span>
        );
      case 'UNKNOWN':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            <span>UNKNOWN</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800/80 text-slate-400 border border-slate-700/60">
            NEUTRAL
          </span>
        );
    }
  };

  const getTransportIcon = (transportState: string) => {
    if (transportState === 'TLS_PROTECTED') {
      return <Lock className="w-3.5 h-3.5 text-emerald-400 inline mr-1" />;
    }
    if (transportState === 'TLS_AVAILABLE') {
      return <Shield className="w-3.5 h-3.5 text-amber-400 inline mr-1" />;
    }
    return <Unlock className="w-3.5 h-3.5 text-rose-400 inline mr-1" />;
  };

  if (!activeReplay || events.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
        <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 className="text-base font-semibold text-slate-200">No Security Replay Events Available</h3>
        <p className="text-xs text-slate-400 mt-1">The current investigation does not contain any reconstructed email sessions.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header & Session Switcher */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                <Play className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-white tracking-tight">
                    Security Replay
                  </h2>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      investigation.data_source === 'REAL_CAPTURE'
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                        : 'bg-amber-500/15 text-amber-300 border border-amber-500/40'
                    }`}
                  >
                    {investigation.data_source || (investigation.is_simulated ? 'SIMULATED' : 'REAL CAPTURE')}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Reconstructed security-relevant events from captured network evidence.
                </p>
              </div>
            </div>
          </div>

          {/* Session Selector Pills */}
          {replays.length > 1 && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-slate-400">Sessions ({replays.length}):</span>
              {replays.map((r) => (
                <button
                  key={r.session_id}
                  onClick={() => setSelectedSessionId(r.session_id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                    selectedSessionId === r.session_id
                      ? 'bg-indigo-600 text-white shadow-sm border border-indigo-500'
                      : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 border border-slate-700'
                  }`}
                >
                  <span className="font-mono">{r.protocol}</span>
                  <span className="text-slate-400 font-mono">({r.summary.client_endpoint})</span>
                  {r.summary.highest_security_state === 'CRITICAL' && (
                    <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Replay Summary Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-4 border-t border-slate-800 text-xs">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[11px]">Session Endpoints</span>
            <span className="text-slate-200 font-mono font-medium truncate block mt-0.5">
              {activeReplay.summary.client_endpoint} → {activeReplay.summary.server_endpoint}
            </span>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[11px]">Final Transport</span>
            <span className="text-slate-200 font-medium flex items-center mt-0.5 font-mono">
              {getTransportIcon(activeReplay.summary.final_transport)}
              {activeReplay.summary.final_transport}
            </span>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[11px]">Event Count / Duration</span>
            <span className="text-slate-200 font-medium mt-0.5 block">
              {activeReplay.summary.event_count} events · {(activeReplay.summary.duration_ms / 1000).toFixed(2)}s
            </span>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-slate-500 block text-[11px]">Posture Evaluation</span>
              <div className="mt-1">{getSecurityStateBadge(activeReplay.summary.highest_security_state)}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Critical Turning Point Spotlight */}
      {activeReplay.critical_moment && (
        <div className="bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-900 border-l-4 border-rose-500 border-y border-r border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-rose-500/15 text-rose-400 mt-0.5">
                <Flame className="w-5 h-5 text-rose-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-rose-300 bg-rose-950/80 px-2 py-0.5 rounded border border-rose-800/80">
                    Critical Moment
                  </span>
                  <span className="text-xs font-mono text-slate-400">{activeReplay.critical_moment.rule_id}</span>
                </div>
                <h4 className="text-sm font-bold text-white mt-1">
                  {activeReplay.critical_moment.title}
                </h4>
                <p className="text-xs text-rose-200/90 mt-0.5 leading-relaxed">
                  Authentication occurred while the session remained unencrypted, despite STARTTLS being available.
                </p>
              </div>
            </div>
            <button
              onClick={() => {
                const idx = events.findIndex((e) => e.event_id === activeReplay.critical_moment?.event_id);
                if (idx !== -1) {
                  setCurrentStepIndex(idx);
                }
              }}
              className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition flex items-center gap-1.5 self-start sm:self-center shadow-sm shrink-0"
            >
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>Jump to Critical Event</span>
            </button>
          </div>
        </div>
      )}

      {/* Playback Control Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          {/* Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleRestart}
              title="Restart Replay"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition border border-slate-700"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
            <button
              onClick={handlePrev}
              disabled={currentStepIndex === 0}
              title="Previous Step"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition border border-slate-700"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={handlePlayPause}
              title={isPlaying ? 'Pause' : 'Play'}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition flex items-center gap-2 shadow-sm"
            >
              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              <span>{isPlaying ? 'Pause' : currentStepIndex >= events.length - 1 ? 'Replay' : 'Play'}</span>
            </button>
            <button
              onClick={handleNext}
              disabled={currentStepIndex === events.length - 1}
              title="Next Step"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition border border-slate-700"
            >
              <ChevronRight className="w-4 h-4" />
            </button>

            {/* Speed Selector */}
            <div className="flex items-center gap-1 ml-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
              {[0.5, 1.0, 2.0].map((spd) => (
                <button
                  key={spd}
                  onClick={() => setPlaybackSpeed(spd)}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition ${
                    playbackSpeed === spd
                      ? 'bg-indigo-600 text-white font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {spd}x
                </button>
              ))}
            </div>
          </div>

          {/* Progress Bar */}
          <div className="flex items-center gap-3 flex-1 max-w-md">
            <span className="text-xs text-slate-400 whitespace-nowrap">
              Step {currentStepIndex + 1} of {events.length}
            </span>
            <div className="relative flex-1 bg-slate-800 h-2 rounded-full overflow-hidden cursor-pointer">
              <div
                className="bg-indigo-500 h-full transition-all duration-200"
                style={{
                  width: `${((currentStepIndex + 1) / events.length) * 100}%`,
                }}
              ></div>
            </div>
            <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
              +{((currentEvent?.relative_time_ms || 0) / 1000).toFixed(3)}s
            </span>
          </div>
        </div>
      </div>

      {/* Main Grid: Reconstructed Sequence (Left) + Detail Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Sequence Diagram Visualizer */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col">
          {/* Participant Headers */}
          <div className="grid grid-cols-2 gap-4 pb-4 border-b border-slate-800 text-center text-xs">
            <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-center gap-2 text-indigo-300">
              <Laptop className="w-4 h-4 text-indigo-400" />
              <div>
                <span className="font-semibold block">Client</span>
                <span className="text-slate-500 font-mono text-[11px]">{activeReplay.summary.client_endpoint}</span>
              </div>
            </div>
            <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-center gap-2 text-indigo-300">
              <Server className="w-4 h-4 text-indigo-400" />
              <div>
                <span className="font-semibold block">Mail Server</span>
                <span className="text-slate-500 font-mono text-[11px]">{activeReplay.summary.server_endpoint}</span>
              </div>
            </div>
          </div>

          {/* Events Stream */}
          <div className="space-y-3 mt-4 overflow-y-auto max-h-[580px] pr-2">
            {events.map((evt, idx) => {
              const isCurrent = idx === currentStepIndex;
              const isPast = idx < currentStepIndex;

              const isClientToServer = evt.direction === 'CLIENT_TO_SERVER';
              const isServerToClient = evt.direction === 'SERVER_TO_CLIENT';
              const isInternal = evt.direction === 'INTERNAL';

              let borderClass = 'border-slate-800/80 bg-slate-950/40 hover:border-slate-700';

              if (evt.security_state === 'CRITICAL') {
                borderClass = isCurrent
                  ? 'border-rose-500 bg-rose-950/40 ring-1 ring-rose-500'
                  : 'border-rose-900/40 bg-rose-950/15 hover:border-rose-700';
              } else if (evt.security_state === 'WARNING') {
                borderClass = isCurrent
                  ? 'border-amber-500 bg-amber-950/30 ring-1 ring-amber-500'
                  : 'border-amber-900/40 bg-amber-950/15 hover:border-amber-700';
              } else if (evt.security_state === 'SECURE') {
                borderClass = isCurrent
                  ? 'border-emerald-500 bg-emerald-950/30 ring-1 ring-emerald-500'
                  : 'border-emerald-900/40 bg-emerald-950/15 hover:border-emerald-700';
              } else if (isCurrent) {
                borderClass = 'border-indigo-500 bg-indigo-950/40 ring-1 ring-indigo-500';
              }

              return (
                <div
                  key={evt.event_id}
                  onClick={() => {
                    setIsPlaying(false);
                    setCurrentStepIndex(idx);
                  }}
                  className={`p-3.5 rounded-xl border transition cursor-pointer relative ${borderClass} ${
                    !isCurrent && !isPast ? 'opacity-75' : 'opacity-100'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    {/* Timing */}
                    <div className="flex items-center gap-1.5 text-xs text-slate-400">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <span className="font-mono text-[11px]">+{((evt.relative_time_ms || 0) / 1000).toFixed(3)}s</span>
                      <span className="text-slate-600">•</span>
                      <span className="font-mono text-[11px] text-slate-500">{evt.evidence_source}</span>
                    </div>

                    {/* State */}
                    <div>{getSecurityStateBadge(evt.security_state)}</div>
                  </div>

                  {/* Flow Direction & Title */}
                  <div className="mt-2 flex items-center gap-3">
                    {isClientToServer && (
                      <div className="flex items-center gap-2 flex-1 text-slate-300">
                        <span className="text-xs font-semibold text-indigo-400">Client</span>
                        <div className="flex-1 flex items-center">
                          <div className="h-0.5 flex-1 bg-gradient-to-r from-indigo-500 via-indigo-400 to-indigo-500"></div>
                          <ArrowRight className="w-3.5 h-3.5 text-indigo-400 -ml-1" />
                        </div>
                        <span className="text-xs text-slate-500">Server</span>
                      </div>
                    )}

                    {isServerToClient && (
                      <div className="flex items-center gap-2 flex-1 text-slate-300">
                        <span className="text-xs text-slate-500">Client</span>
                        <div className="flex-1 flex items-center">
                          <ArrowLeft className="w-3.5 h-3.5 text-indigo-400 -mr-1" />
                          <div className="h-0.5 flex-1 bg-gradient-to-r from-indigo-500 via-indigo-400 to-indigo-500"></div>
                        </div>
                        <span className="text-xs font-semibold text-indigo-400">Server</span>
                      </div>
                    )}

                    {isInternal && (
                      <div className="flex-1 text-center">
                        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-rose-300 border border-rose-500/30">
                          State Assessment Notice
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="mt-2 flex items-center justify-between gap-2">
                    <h4 className="text-sm font-semibold text-white">
                      {evt.title}
                    </h4>
                    <span className="text-xs font-mono text-slate-400 flex items-center">
                      {getTransportIcon(evt.transport_state)}
                      {evt.transport_state}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 mt-1 leading-relaxed font-sans">
                    {evt.description}
                  </p>

                  {/* Linked Rule Findings */}
                  {evt.related_rule_ids.length > 0 && (
                    <div className="mt-2.5 flex items-center gap-1.5 flex-wrap">
                      <span className="text-[11px] text-slate-500 font-medium">Rule:</span>
                      {evt.related_rule_ids.map((rId) => (
                        <button
                          key={rId}
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onNavigateToFinding) onNavigateToFinding(rId);
                          }}
                          className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-950/80 text-rose-300 border border-rose-800 hover:bg-rose-900 transition flex items-center gap-1"
                        >
                          <AlertTriangle className="w-3 h-3 text-rose-400" />
                          <span>{rId}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Event Details Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm sticky top-20">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-white">
                  Event Inspection Detail
                </h3>
              </div>
              {currentEvent && getSecurityStateBadge(currentEvent.security_state)}
            </div>

            {currentEvent ? (
              <div className="mt-4 space-y-4 text-xs">
                {/* Event Headline */}
                <div>
                  <span className="text-slate-500 uppercase font-semibold block text-[10px] tracking-wider">Title</span>
                  <h4 className="text-base font-bold text-white mt-0.5">{currentEvent.title}</h4>
                  <p className="text-slate-300 mt-1 leading-relaxed font-sans">{currentEvent.description}</p>
                </div>

                {/* Evidence and Transport */}
                <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Evidence Source</span>
                    <span className="text-slate-200 font-mono font-medium">{currentEvent.evidence_source}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Transport Security</span>
                    <span className="text-slate-200 font-medium flex items-center mt-0.5 font-mono">
                      {getTransportIcon(currentEvent.transport_state)}
                      {currentEvent.transport_state}
                    </span>
                  </div>
                </div>

                {/* Direction and Type */}
                <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Direction</span>
                    <span className="text-slate-200 font-medium">{currentEvent.direction.replace(/_/g, ' ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Event Type</span>
                    <span className="text-slate-200 font-medium">{currentEvent.event_type.replace(/_/g, ' ')}</span>
                  </div>
                </div>

                {/* Security Impact */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider mb-1.5">
                    Security Analysis Context
                  </span>
                  {currentEvent.security_state === 'CRITICAL' ? (
                    <div className="text-rose-300 flex items-start gap-2">
                      <AlertOctagon className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <strong className="block text-rose-200 font-semibold">Severe Transport Security Risk</strong>
                        <p className="text-xs text-rose-300/90 mt-0.5 font-sans leading-relaxed">
                          Authentication credentials or confidential transaction data were observed over an unencrypted transport channel.
                        </p>
                      </div>
                    </div>
                  ) : currentEvent.security_state === 'WARNING' ? (
                    <div className="text-amber-300 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <div>
                        <strong className="block text-amber-200 font-semibold">Configuration Warning</strong>
                        <p className="text-xs text-amber-300/90 mt-0.5 font-sans leading-relaxed">
                          Encryption was offered or negotiated with legacy parameters, leaving potential downgrade or plain-text exposure.
                        </p>
                      </div>
                    </div>
                  ) : currentEvent.security_state === 'SECURE' ? (
                    <div className="text-emerald-300 flex items-start gap-2">
                      <Shield className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <div>
                        <strong className="block text-emerald-200 font-semibold">Cryptographically Protected</strong>
                        <p className="text-xs text-emerald-300/90 mt-0.5 font-sans leading-relaxed">
                          Operation was performed inside verified transport security parameters.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-slate-400 font-sans">Standard protocol exchange in connection lifecycle.</p>
                  )}
                </div>

                {/* Associated Finding */}
                {currentEvent.related_rule_ids.length > 0 && (
                  <div className="p-3 rounded-lg bg-indigo-950/20 border border-indigo-500/30">
                    <span className="text-indigo-400 block text-[10px] uppercase font-semibold tracking-wider mb-1">
                      Related Security Finding
                    </span>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-indigo-300 font-bold">
                        {currentEvent.related_rule_ids.join(', ')}
                      </span>
                      {onNavigateToFinding && (
                        <button
                          onClick={() => onNavigateToFinding(currentEvent.related_rule_ids[0])}
                          className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition"
                        >
                          View Finding →
                        </button>
                      )}
                    </div>
                  </div>
                )}

                {/* Privacy Guarantee Note */}
                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-start gap-2 text-slate-400 text-xs">
                  <Info className="w-3.5 h-3.5 text-indigo-400 mt-0.5 shrink-0" />
                  <p className="leading-normal">
                    Privacy Filter: Credential strings, AUTH payloads, sender/recipient addresses, and message bodies are sanitized before analysis.
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-slate-500 text-center py-6">Select an event to view details</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
