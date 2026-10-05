import React, { useState, useRef } from 'react';
import { 
  Upload, 
  ShieldCheck, 
  CheckCircle2, 
  AlertCircle, 
  ArrowRight,
  FileCode,
  RefreshCw,
  Sparkles,
  Terminal
} from 'lucide-react';
import { Investigation, UploadProgressState } from '../types';
import { analyzeCapture } from '../services/api';

interface UploadCaptureProps {
  onViewDemo: () => void;
  onInvestigationLoaded: (investigation: Investigation) => void;
}

export const UploadCapture: React.FC<UploadCaptureProps> = ({
  onViewDemo,
  onInvestigationLoaded,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [uploadState, setUploadState] = useState<UploadProgressState>('IDLE');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analyzedInvestigation, setAnalyzedInvestigation] = useState<Investigation | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = (file: File) => {
    if (!/\.(pcap|pcapng)$/i.test(file.name) || file.size > 50 * 1024 * 1024) {
      setErrorMessage('Choose a .pcap or .pcapng file up to 50 MB.'); setUploadState('FAILED'); return;
    }
    setSelectedFile(file);
    setUploadState('IDLE');
    setErrorMessage(null);
    setAnalyzedInvestigation(null);
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;

    setUploadState('UPLOADING');
    setErrorMessage(null);

    try {
      setUploadState('ANALYSING');
      const result = await analyzeCapture(selectedFile);
      setAnalyzedInvestigation(result);
      setUploadState('COMPLETE');
      onInvestigationLoaded(result);
    } catch (err: unknown) {
      setUploadState('FAILED');
      const msg = err instanceof Error ? err.message : 'Failed to analyze network capture.';
      setErrorMessage(msg);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title & Purpose */}
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-bold text-white tracking-tight">
          Upload Network Capture
        </h2>
        <p className="text-xs text-slate-400 max-w-xl mx-auto leading-relaxed">
          SecureMailScope reconstructs SMTP, IMAP, and POP3 network sessions offline to evaluate transport-security integrity.
        </p>
      </div>

      {/* Privacy Guarantee Box */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 text-xs">
        <div className="flex items-start space-x-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mt-0.5 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <span className="font-semibold text-slate-200 text-xs">
              Privacy Principle & Offline Security
            </span>
            <p className="text-slate-300 leading-relaxed font-sans">
              "Captured traffic is intended to be analysed locally. SecureMailScope does not require access to email message contents or credentials."
            </p>
            <p className="text-slate-400 text-[11px]">
              Only transport metadata (TLS ClientHello, ServerHello, STARTTLS commands, cipher negotiation) is evaluated.
            </p>
          </div>
        </div>
      </div>

      {/* Drag & Drop Zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        role="button" tabIndex={0} aria-label="Choose packet capture"
        onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inputRef.current?.click()}}}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-200 ${
          dragActive
            ? 'border-sky-500 bg-sky-950/20'
            : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/80'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          onChange={handleChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <Upload className="w-7 h-7" />
          </div>

          <div>
            <span className="text-sm font-semibold text-slate-200 block">
              Click to select or drag & drop network capture
            </span>
            <span className="text-xs text-slate-400 mt-1 block">
              Supported formats: .pcap, .pcapng (Max 50 MB)
            </span>
          </div>

          <div className="text-xs text-slate-500">
            Directly dissected with local TShark session engine
          </div>
        </div>
      </div>

      {/* Selected File Card & Actions */}
      {selectedFile && (
        <div className="bg-slate-900/90 border border-sky-500/30 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
                <FileCode className="w-5 h-5" />
              </div>
              <div>
                <div className="text-sm font-bold text-white font-mono">{selectedFile.name}</div>
                <div className="text-xs text-slate-400">
                  {(selectedFile.size / 1024).toFixed(1)} KB • Ready for Ingestion
                </div>
              </div>
            </div>

            {/* Analysis Action Button */}
            {uploadState === 'IDLE' && (
              <button
                onClick={handleStartAnalysis}
                className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs transition shadow-sm"
              >
                <Terminal className="w-4 h-4" />
                <span>Start PCAP Analysis</span>
              </button>
            )}

            {/* Active Analysis State Spinner */}
            {(uploadState === 'UPLOADING' || uploadState === 'ANALYSING') && (
              <div className="flex items-center space-x-2 bg-sky-950/80 text-sky-300 border border-sky-800/60 px-4 py-2 rounded-xl text-xs">
                <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
                <span>{uploadState === 'UPLOADING' ? 'Uploading capture...' : 'Analysing with TShark...'}</span>
              </div>
            )}

            {/* Complete State */}
            {uploadState === 'COMPLETE' && (
              <div className="flex items-center space-x-2 bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 px-4 py-2 rounded-xl text-xs">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Capture analysed successfully</span>
              </div>
            )}
          </div>

          {/* Success Summary View */}
          {uploadState === 'COMPLETE' && analyzedInvestigation && (
            <div className="bg-emerald-950/20 border border-emerald-900/60 rounded-xl p-4 text-xs text-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="font-bold text-emerald-300">
                    Session Reconstruction Finished
                  </span>
                </div>
                {analyzedInvestigation.sha256_short && (
                  <span className="text-xs text-slate-400 font-mono">
                    SHA-256: {analyzedInvestigation.sha256_short}
                  </span>
                )}
              </div>

              <p className="text-slate-300 leading-relaxed font-sans">
                Extracted <strong className="text-white">{analyzedInvestigation.summary.sessions_analyzed}</strong> mail transport session(s) across <strong className="text-white">{analyzedInvestigation.nodes.length}</strong> host(s).
              </p>

              <div className="flex justify-end pt-2">
                <button
                  onClick={onViewDemo}
                  className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition shadow-sm"
                >
                  <span>Open Reconstructed Investigation</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Error Message View */}
          {uploadState === 'FAILED' && errorMessage && (
            <div className="bg-rose-950/30 border border-rose-900/80 rounded-xl p-4 text-xs text-rose-200 space-y-2">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span className="font-bold text-rose-300">
                  Analysis Failed
                </span>
              </div>
              <p className="text-xs leading-relaxed pl-6 text-rose-300 font-sans">
                {errorMessage}
              </p>
              {errorMessage.includes('TShark is required') && (
                <div className="mt-2 pl-6 text-xs text-slate-400">
                  Tip: Install Wireshark from <a href="https://www.wireshark.org" target="_blank" rel="noreferrer" className="text-sky-400 underline">wireshark.org</a> and ensure <code className="text-slate-200 font-mono">tshark</code> is in your system PATH.
                </div>
              )}
              <div className="pt-2 flex justify-end">
                <button
                  onClick={handleStartAnalysis}
                  className="px-4 py-1.5 rounded-lg bg-rose-900/80 hover:bg-rose-800 text-rose-100 text-xs font-semibold transition"
                >
                  Retry Analysis
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Switch to Demo Mode Card */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2 text-slate-400">
          <Sparkles className="w-4 h-4 text-amber-400" />
          <span>Need to demonstrate without uploading a live PCAP?</span>
        </div>
        <button
          onClick={onViewDemo}
          className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition flex items-center space-x-1.5"
        >
          <span>View Demo Investigation (Simulated)</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
