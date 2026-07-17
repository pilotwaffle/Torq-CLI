import React, { useState, useEffect, useRef } from "react";
import { ModelNode, PipelineRun, NodeStatus, StageExecution } from "./types";
import ModelPoolPanel from "./components/ModelPoolPanel";
import PipelineSetup from "./components/PipelineSetup";
import PipelineExecution from "./components/PipelineExecution";
import IntegrityReport from "./components/IntegrityReport";
import { Activity, ShieldCheck, Play, HelpCircle, History, FileText, Settings, Cpu, Shield, Coins, AlertCircle } from "lucide-react";

// Default models
const INITIAL_MODELS: ModelNode[] = [
  {
    id: "node-a",
    name: "GPT-4o / Pro-Active",
    provider: "OpenAI Paid Node",
    role: "Fast Generator",
    costPerHr: 15.00,
    status: NodeStatus.Active,
    description: "Highly adaptive agent optimized for high-speed generation of blueprints, drafts, and scaffolding.",
  },
  {
    id: "node-b",
    name: "Claude 3.5 / Logic",
    provider: "Anthropic Paid Node",
    role: "Logical Refiner",
    costPerHr: 24.00,
    status: NodeStatus.Active,
    description: "Exceptional code quality, strict logical formatting, and highly detailed optimizations.",
  },
  {
    id: "node-c",
    name: "Gemini 1.5 Pro / Analysis",
    provider: "Google Cloud Node",
    role: "Integrity Reviewer",
    costPerHr: 18.00,
    status: NodeStatus.Active,
    description: "Massive context window, superb at identifying critical vulnerabilities and logical gaps.",
  },
  {
    id: "node-d",
    name: "Mistral / Synthesizer",
    provider: "Mistral AI Node",
    role: "Generalist Agent",
    costPerHr: 12.00,
    status: NodeStatus.Active,
    description: "Excellent at markdown conversion, multi-modal formatting, and general purpose synthesis.",
  },
  {
    id: "node-e",
    name: "Llama 3 / Support",
    provider: "Meta Llama Host",
    role: "Idle Backup",
    costPerHr: 8.00,
    status: NodeStatus.Idle,
    description: "A lightweight node reserved for low-priority tasks, basic QA, or backup substitution.",
  }
];

export default function App() {
  const [models, setModels] = useState<ModelNode[]>(() => {
    const saved = localStorage.getItem("model_pool_nodes");
    return saved ? JSON.parse(saved) : INITIAL_MODELS;
  });

  const [history, setHistory] = useState<PipelineRun[]>(() => {
    const saved = localStorage.getItem("pipeline_run_history");
    return saved ? JSON.parse(saved) : [];
  });

  const [activeRun, setActiveRun] = useState<PipelineRun | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [activeTab, setActiveTab] = useState<"orchestrator" | "security" | "history">("orchestrator");
  
  const [liveConfig, setLiveConfig] = useState({
    liveModeAvailable: false,
    hasApiKey: false,
  });

  const [forceSimulate, setForceSimulate] = useState<boolean>(() => {
    return localStorage.getItem("force_simulate") === "true";
  });

  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Sync to localStorage
  useEffect(() => {
    localStorage.setItem("model_pool_nodes", JSON.stringify(models));
  }, [models]);

  useEffect(() => {
    localStorage.setItem("pipeline_run_history", JSON.stringify(history));
  }, [history]);

  useEffect(() => {
    localStorage.setItem("force_simulate", String(forceSimulate));
  }, [forceSimulate]);

  // Fetch API Config on mount
  useEffect(() => {
    fetch("/api/config")
      .then((res) => res.json())
      .then((data) => {
        setLiveConfig({
          liveModeAvailable: data.liveModeAvailable,
          hasApiKey: data.hasApiKey,
        });
        if (!data.hasApiKey) {
          setForceSimulate(true);
        }
      })
      .catch((err) => console.error("Error checking API config:", err));
  }, []);

  // Handle running the pipeline
  const handleTriggerRun = async (
    prompt: string,
    assignments: Record<string, string>,
    mode: "auto_substitute" | "strict_block"
  ) => {
    setIsRunning(true);
    setCurrentStageIdx(0);
    setActiveRun(null);

    try {
      const response = await fetch("/api/run-pipeline", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt,
          modelAssignments: assignments,
          enforcementMode: mode,
          customPool: models,
          forceSimulate,
        }),
      });

      if (!response.ok) {
        throw new Error("Backend workload error");
      }

      const finalResult = (await response.json()) as PipelineRun;

      // We have the final result. Now we animate the steps sequentially to give a premium, tactical feedback loop
      let stageCounter = 0;
      
      // Setup a visual playback of each stage finishing
      timerRef.current = setInterval(() => {
        if (stageCounter < 5) {
          // Construct an intermediate mock run state showing only completed stages up to stageCounter
          const partialExecutions: Record<string, StageExecution> = {};
          const stageKeys = ["init", "generate", "refine", "review", "export"];
          
          for (let j = 0; j <= stageCounter; j++) {
            const key = stageKeys[j];
            if (finalResult.stageExecutions[key]) {
              partialExecutions[key] = finalResult.stageExecutions[key];
            }
          }

          // Check if intermediate blocked
          const hasBlocked = Object.values(partialExecutions).some(e => e.status === "blocked");

          setActiveRun({
            ...finalResult,
            status: hasBlocked ? "blocked" : stageCounter === 4 ? finalResult.status : "running",
            stageExecutions: partialExecutions,
            totalTokens: Object.values(partialExecutions).reduce((sum, e) => sum + (e.tokensUsed || 0), 0),
            totalCost: parseFloat(Object.values(partialExecutions).reduce((sum, e) => sum + (e.cost || 0), 0).toFixed(4)),
          });

          if (hasBlocked) {
            // Stop animations early
            setIsRunning(false);
            if (timerRef.current) clearInterval(timerRef.current);
            // Append to history
            setHistory(prev => [finalResult, ...prev]);
            return;
          }

          setCurrentStageIdx(stageCounter);
          stageCounter++;
        } else {
          // Finished visualizer
          setIsRunning(false);
          setActiveRun(finalResult);
          if (timerRef.current) clearInterval(timerRef.current);
          
          // Append to history
          setHistory(prev => [finalResult, ...prev]);
        }
      }, 1500); // 1.5 seconds per stage for clean visual pacing

    } catch (err) {
      console.error("Pipeline run failed:", err);
      setIsRunning(false);
      alert("Failed to compile or execute pipeline workload. Check backend connections.");
    }
  };

  const handleClearRun = () => {
    setActiveRun(null);
    setCurrentStageIdx(0);
    setIsRunning(false);
    if (timerRef.current) clearInterval(timerRef.current);
  };

  const handleLoadHistory = (run: PipelineRun) => {
    setActiveRun(run);
    setActiveTab("orchestrator");
    // visual index is complete
    setCurrentStageIdx(4);
  };

  const handleClearHistory = () => {
    if (confirm("Are you sure you want to clear the system security ledgers and workload history?")) {
      setHistory([]);
    }
  };

  return (
    <div className="flex h-screen w-full bg-dark-bg text-gray-200 overflow-hidden" id="app-root">
      {/* 1. Sidebar - Model Labor Pool */}
      <ModelPoolPanel models={models} onUpdateModels={setModels} />

      {/* 2. Main content block */}
      <main className="flex-1 flex flex-col h-full overflow-hidden" id="main-workspace">
        {/* Header bar */}
        <header className="h-20 bg-dark-sidebar border-b border-dark-border px-8 flex items-center justify-between shrink-0" id="master-header">
          <div className="flex items-baseline gap-4">
            <h1 className="font-serif text-2xl tracking-wide text-gold flex items-center gap-2">
              Master Pipeline Orchestrator
            </h1>
            <span className="font-mono text-[10px] text-gray-500 tracking-widest hidden sm:inline">
              CFG: ROLE_SEGREGATION_STRICT
            </span>
          </div>

          <div className="flex items-center gap-6">
            {/* Status indicator */}
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${liveConfig.hasApiKey ? "bg-emerald-500 animate-pulse" : "bg-gold/40 animate-pulse"}`} />
              <div className="text-right">
                <span className="text-[9px] text-gray-500 uppercase font-mono block">Engine Status</span>
                <span className="text-xs font-semibold text-gray-300">
                  {liveConfig.hasApiKey ? "Live Gemini Node Active" : "Simulated Local Proxy"}
                </span>
              </div>
            </div>

            {/* General metrics */}
            <div className="hidden md:flex gap-6 items-center border-l border-dark-border pl-6">
              <div className="text-right">
                <span className="text-[9px] text-gray-500 uppercase font-mono block">Total Processed Runs</span>
                <span className="text-xs font-mono text-white">{history.length} Jobs</span>
              </div>
              <div className="text-right">
                <span className="text-[9px] text-gray-500 uppercase font-mono block">Cumulative Sched Billing</span>
                <span className="text-xs font-mono text-gold font-medium">
                  ${history.reduce((sum, r) => sum + r.totalCost, 0).toFixed(4)}
                </span>
              </div>
            </div>
          </div>
        </header>

        {/* Tab Selection */}
        <div className="px-8 bg-dark-sidebar/40 border-b border-dark-border flex items-center justify-between shrink-0" id="app-tabs">
          <div className="flex space-x-1 py-1">
            <button
              onClick={() => setActiveTab("orchestrator")}
              className={`px-4 py-3 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
                activeTab === "orchestrator"
                  ? "border-gold text-gold font-semibold"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <Activity className="w-4 h-4" /> Pipeline Orchestrator
            </button>
            <button
              onClick={() => setActiveTab("security")}
              className={`px-4 py-3 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
                activeTab === "security"
                  ? "border-gold text-gold font-semibold"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <ShieldCheck className="w-4 h-4" /> Security Ledger
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`px-4 py-3 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
                activeTab === "history"
                  ? "border-gold text-gold font-semibold"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <History className="w-4 h-4" /> Workload History ({history.length})
            </button>
          </div>

          {!liveConfig.hasApiKey && (
            <div className="flex items-center gap-1.5 text-xs text-gold bg-gold/5 border border-gold/15 px-3 py-1 rounded">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span className="text-[11px]">Add a <strong>GEMINI_API_KEY</strong> in Secrets panel to unlock live model queries!</span>
            </div>
          )}
        </div>

        {/* Workspace body */}
        <div className="flex-1 overflow-y-auto p-8 space-y-6" id="workspace-viewport">
          {activeTab === "orchestrator" && (
            <div className="space-y-8 animate-fade-in">
              <PipelineSetup
                models={models}
                onTriggerRun={handleTriggerRun}
                isRunning={isRunning}
                onClearRun={handleClearRun}
                forceSimulate={forceSimulate}
                onToggleForceSimulate={setForceSimulate}
                hasApiKey={liveConfig.hasApiKey}
              />
              <PipelineExecution
                activeRun={activeRun}
                isRunning={isRunning}
                currentRunningStageIndex={currentStageIdx}
              />
            </div>
          )}

          {activeTab === "security" && (
            <div className="animate-fade-in">
              <IntegrityReport
                activeRun={activeRun}
                history={history}
                models={models}
              />
            </div>
          )}

          {activeTab === "history" && (
            <div className="bg-dark-card border border-dark-border rounded p-6 shadow-xl space-y-4 animate-fade-in" id="history-container">
              <div className="flex items-center justify-between border-b border-dark-border pb-4">
                <div>
                  <h3 className="font-serif text-lg text-gold tracking-wide">Archived Workloads</h3>
                  <p className="text-xs text-gray-500 mt-1">Audit trail of previously executed model workflows and generated codebases</p>
                </div>
                {history.length > 0 && (
                  <button
                    onClick={handleClearHistory}
                    className="text-xs text-red-500 hover:text-red-400 font-medium border border-red-500/20 hover:border-red-500/40 px-3 py-1.5 rounded transition-all bg-red-500/5"
                  >
                    Clear Archives
                  </button>
                )}
              </div>

              {history.length === 0 ? (
                <div className="p-12 border border-dashed border-dark-border rounded text-center text-xs text-gray-500 italic">
                  No historical records found. Run a model workload in the orchestrator to populate the archives.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {history.map((run) => (
                    <div
                      key={run.id}
                      className="p-4 bg-dark-bg border border-dark-border rounded hover:border-gold/30 transition-all cursor-pointer flex flex-col justify-between"
                      onClick={() => handleLoadHistory(run)}
                    >
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-gray-500 font-mono">ID: {run.id.toUpperCase()}</span>
                          <span className="text-[10px] text-gray-500 font-mono">{new Date(run.createdAt).toLocaleString()}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-white truncate">"{run.prompt}"</h4>
                      </div>

                      <div className="mt-4 pt-3 border-t border-dark-border/40 flex items-center justify-between text-xs">
                        <div className="flex items-center gap-3">
                          <span className="text-gray-400">
                            Tokens: <strong className="text-white font-mono">{run.totalTokens.toLocaleString()}</strong>
                          </span>
                          <span className="text-gray-400">
                            Cost: <strong className="text-gold font-mono">${run.totalCost.toFixed(4)}</strong>
                          </span>
                        </div>
                        
                        <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold tracking-wider uppercase font-mono border ${
                          run.status === "completed"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : run.status === "blocked"
                            ? "bg-red-500/10 text-red-400 border-red-500/20"
                            : "bg-amber-500/10 text-amber-500 border-amber-500/20"
                        }`}>
                          {run.status === "completed" ? "SECURE_OK" : run.status.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
