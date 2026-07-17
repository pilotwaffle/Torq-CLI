import React, { useState } from "react";
import { PipelineRun, StageExecution, StageDetails } from "../types";
import { AlertTriangle, Clock, Coins, Database, Eye, Terminal, FileText, CheckCircle2, ChevronRight, Ban, HelpCircle, Lock, ShieldAlert, Cpu, RefreshCw } from "lucide-react";

interface PipelineExecutionProps {
  activeRun: PipelineRun | null;
  isRunning: boolean;
  currentRunningStageIndex: number;
}

const STAGES: StageDetails[] = [
  { id: "init", name: "01. Init", label: "Init Context", description: "Configures settings, parameters, and initializes container." },
  { id: "generate", name: "02. Generate", label: "Generate Draft", description: "Creates initial drafts, schemas, and structural text." },
  { id: "refine", name: "03. Refine", label: "Refine Draft", description: "Applies logical detailing, optimizes structures, and handles typing." },
  { id: "review", name: "04. Review", label: "Peer Review", description: "Segregates roles to perform strict quality and integrity audits." },
  { id: "export", name: "05. Export", label: "Export Package", description: "Prepares verified deliverables, formats layouts, and exports package." },
];

function getHtmlPreviewContent(output: string | undefined): string | null {
  if (!output) return null;

  // 1. Try to find content inside ```html ... ``` or ``` ... ```
  const markdownCodeBlockRegex = /```(?:html)?\s*([\s\S]*?)```/i;
  const match = output.match(markdownCodeBlockRegex);
  if (match && match[1]) {
    const code = match[1].trim();
    if (code.includes("<html") || code.includes("<!DOCTYPE") || code.includes("<div") || code.includes("<body")) {
      return code;
    }
  }

  // 2. Try to find the bounds of standard HTML tags starting with <!DOCTYPE html> or <html
  const lowerOutput = output.toLowerCase();
  const docTypeIdx = lowerOutput.indexOf("<!doctype html>");
  const htmlStartIdx = lowerOutput.indexOf("<html");
  const htmlEndIdx = lowerOutput.lastIndexOf("</html>");

  let startIdx = -1;
  if (docTypeIdx !== -1) {
    startIdx = docTypeIdx;
  } else if (htmlStartIdx !== -1) {
    startIdx = htmlStartIdx;
  }

  if (startIdx !== -1 && htmlEndIdx !== -1 && htmlEndIdx > startIdx) {
    return output.substring(startIdx, htmlEndIdx + 7);
  }

  // 3. Fallback: if it has <!DOCTYPE html> or <html, but no closing </html>
  if (docTypeIdx !== -1) {
    return output.substring(docTypeIdx);
  }
  if (htmlStartIdx !== -1) {
    return output.substring(htmlStartIdx);
  }

  // 4. If it contains basic structure
  if (output.includes("<div") || output.includes("<body") || output.includes("<script") || output.includes("<canvas")) {
    return output;
  }

  return null;
}

export default function PipelineExecution({ activeRun, isRunning, currentRunningStageIndex }: PipelineExecutionProps) {
  const [selectedStageId, setSelectedStageId] = useState<string>("generate");
  const [activeTab, setActiveTab] = useState<"output" | "logs" | "preview">("output");

  const currentSelectionExecution = activeRun ? activeRun.stageExecutions[selectedStageId] : undefined;

  // Check if output content is renderable as interactive HTML
  const previewHtml = currentSelectionExecution?.status === "completed" 
    ? getHtmlPreviewContent(currentSelectionExecution.output) 
    : null;
  const isPreviewable = !!previewHtml;

  // Auto-redirect or auto-focus preview tab when switching stages
  React.useEffect(() => {
    if (isPreviewable) {
      setActiveTab("preview");
    } else {
      setActiveTab("output");
    }
  }, [selectedStageId, isPreviewable]);

  // Auto-advance selected stage during execution or on load
  React.useEffect(() => {
    if (activeRun) {
      const keys = ["init", "generate", "refine", "review", "export"];
      let highestKey = "init";
      for (const key of keys) {
        if (activeRun.stageExecutions[key]) {
          highestKey = key;
        }
      }
      setSelectedStageId(highestKey);
    }
  }, [activeRun]);

  if (!activeRun) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-lg p-10 flex flex-col items-center justify-center text-center space-y-4 text-gray-500" id="pipeline-execution-empty">
        <Database className="w-12 h-12 text-gray-700 animate-pulse" />
        <div className="space-y-1">
          <h3 className="font-serif text-lg text-gray-400">Master Pipeline Standby</h3>
          <p className="text-xs max-w-sm">No workload is currently running. Select a prompt above and click "Run Model Workload" to start the 5-stage pipeline.</p>
        </div>
      </div>
    );
  }

  // Find currently active stage or latest execution info
  const stageIds = STAGES.map(s => s.id);
  const currentRunningStageId = isRunning && currentRunningStageIndex < STAGES.length ? STAGES[currentRunningStageIndex].id : null;

  // Helper to get state badge
  const getStageBadge = (stageId: string, idx: number) => {
    const exec = activeRun.stageExecutions[stageId];
    
    if (isRunning) {
      if (idx === currentRunningStageIndex) {
        return (
          <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-gold/10 text-gold border border-gold/30 animate-pulse">
            RUNNING
          </span>
        );
      }
      if (idx > currentRunningStageIndex) {
        return (
          <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-dark-bg text-gray-600 border border-dark-border">
            PENDING
          </span>
        );
      }
    }

    if (!exec) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-dark-bg text-gray-600 border border-dark-border">
          STANDBY
        </span>
      );
    }

    if (exec.status === "completed") {
      return (
        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          FINISHED
        </span>
      );
    }

    if (exec.status === "blocked") {
      return (
        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
          BLOCKED
        </span>
      );
    }

    if (exec.status === "skipped") {
      return (
        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-gray-800 text-gray-500 border border-gray-700">
          SKIPPED
        </span>
      );
    }

    return null;
  };

  const getStageBorderColor = (stageId: string, idx: number) => {
    if (selectedStageId === stageId) return "border-gold bg-dark-bg";
    
    const exec = activeRun.stageExecutions[stageId];
    if (isRunning && idx === currentRunningStageIndex) return "border-gold/50 bg-dark-bg/40 animate-pulse";
    
    if (!exec) return "border-dark-border bg-dark-card opacity-60";
    if (exec.status === "completed") return "border-emerald-950 bg-dark-card hover:border-emerald-800";
    if (exec.status === "blocked") return "border-red-950 bg-red-950/5 hover:border-red-800";
    if (exec.status === "skipped") return "border-dark-border opacity-40";

    return "border-dark-border";
  };

  return (
    <div className="space-y-6" id="pipeline-execution-panel">
      {/* Live Quota Warning Fallback Banner */}
      {activeRun.liveFallbackTriggered && (
        <div className="bg-amber-950/20 border border-amber-500/30 rounded p-4 flex items-start gap-3 text-amber-300" id="quota-fallback-warning">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h5 className="text-xs font-bold font-mono tracking-wider uppercase text-amber-400">
              Live API Quota Exhausted (Automatic Fallback Triggered)
            </h5>
            <p className="text-xs text-amber-200/80 leading-relaxed">
              The live Gemini Cloud node returned a rate-limiting quota error (429 Resource Exhausted) or connection issue. To prevent pipeline failure, the execution engine has automatically switched remaining stages to the local simulated proxy models.
            </p>
            {activeRun.liveFallbackReason && (
              <p className="text-[10px] text-amber-400/60 font-mono mt-1">
                Details: {activeRun.liveFallbackReason}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Metrics Banner */}
      <div className="bg-[#080808] border border-dark-border rounded p-4 flex flex-wrap gap-6 items-center justify-between" id="execution-metrics">
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-10 bg-gold rounded-full" />
          <div>
            <span className="text-[10px] text-gray-500 font-mono block uppercase">Active Workload Run</span>
            <h4 className="text-sm font-semibold text-white tracking-wide truncate max-w-xs md:max-w-md">
              "{activeRun.prompt}"
            </h4>
          </div>
        </div>

        <div className="flex gap-6 items-center">
          <div className="text-right">
            <span className="text-[10px] text-gray-500 font-mono block uppercase">Compliance Guard</span>
            {activeRun.status === "blocked" ? (
              <span className="text-xs text-red-400 font-bold flex items-center gap-1 justify-end font-mono">
                <Ban className="w-3.5 h-3.5" /> BLOCKED_SECURE
              </span>
            ) : activeRun.integrityLogs.length > 0 ? (
              <span className="text-xs text-amber-500 font-bold flex items-center gap-1 justify-end font-mono">
                <ShieldAlert className="w-3.5 h-3.5" /> REPLACED_SECURE
              </span>
            ) : isRunning ? (
              <span className="text-xs text-gold font-bold flex items-center gap-1 justify-end font-mono animate-pulse">
                <Cpu className="w-3.5 h-3.5 animate-spin" /> ENFORCING_GUARD
              </span>
            ) : (
              <span className="text-xs text-emerald-400 font-bold flex items-center gap-1 justify-end font-mono">
                <CheckCircle2 className="w-3.5 h-3.5" /> 100% COMPLIANT
              </span>
            )}
          </div>

          <div className="text-right">
            <span className="text-[10px] text-gray-500 font-mono block uppercase">Total Active Tokens</span>
            <span className="text-sm font-mono text-white">
              {activeRun.totalTokens.toLocaleString()}
            </span>
          </div>

          <div className="text-right">
            <span className="text-[10px] text-gray-500 font-mono block uppercase">Workload Cost</span>
            <span className="text-sm font-mono text-gold font-medium">
              ${activeRun.totalCost.toFixed(4)}
            </span>
          </div>
        </div>
      </div>

      {/* Five-Stage Grid (Refuses self-review) */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-1 bg-dark-border border border-dark-border rounded overflow-hidden" id="pipeline-stages-grid">
        {STAGES.map((stage, idx) => {
          const exec = activeRun.stageExecutions[stage.id];
          const isSelected = selectedStageId === stage.id;
          const isCurrentRunning = isRunning && idx === currentRunningStageIndex;
          
          return (
            <button
              key={stage.id}
              onClick={() => setSelectedStageId(stage.id)}
              disabled={!exec && !isCurrentRunning}
              className={`stage p-5 text-left flex flex-col justify-between transition-all duration-300 min-h-[170px] ${getStageBorderColor(stage.id, idx)}`}
              id={`stage-card-${stage.id}`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-serif text-xs text-gray-400 tracking-wider uppercase">
                    {stage.name}
                  </h3>
                  {getStageBadge(stage.id, idx)}
                </div>
                
                <h4 className="text-sm font-semibold text-white mt-1">{stage.label}</h4>
                <p className="text-[11px] text-gray-500 mt-1 leading-relaxed">
                  {stage.description}
                </p>
              </div>

              {exec ? (
                <div className="mt-4 pt-3 border-t border-dark-border/40">
                  <span className="text-[10px] font-mono block text-gray-500 truncate" title={exec.modelName}>
                    {exec.modelId === "system" ? "⚙️ System" : `🤖 ${exec.modelName.split(" / ")[0]}`}
                  </span>
                  {exec.status === "completed" && (
                    <div className="flex items-center justify-between mt-1 text-[10px] text-gray-400 font-mono">
                      <span>{(exec.durationMs / 1000).toFixed(1)}s</span>
                      <span className="text-gold">${exec.cost.toFixed(4)}</span>
                    </div>
                  )}
                  {exec.status === "blocked" && (
                    <span className="text-[10px] font-bold font-mono text-red-500 block mt-1 uppercase">
                      INTEGRITY_SHIELD
                    </span>
                  )}
                </div>
              ) : isCurrentRunning ? (
                <div className="mt-4 pt-3 border-t border-dark-border/40 flex items-center justify-between text-[10px] font-mono text-gold">
                  <span className="flex items-center gap-1">
                    <RefreshCw className="w-3 h-3 animate-spin" /> RUNNING
                  </span>
                  <span>Active...</span>
                </div>
              ) : (
                <div className="mt-4 pt-3 border-t border-dark-border/40 text-[10px] font-mono text-gray-600">
                  Waiting...
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Output & Logs Viewer */}
      {currentSelectionExecution ? (
        <div className="bg-dark-card border border-dark-border rounded shadow-lg overflow-hidden flex flex-col" id="stage-inspector">
          {/* Header */}
          <div className="px-6 py-4 border-b border-dark-border flex flex-wrap gap-4 items-center justify-between bg-black/40">
            <div className="flex items-center gap-3">
              <Database className="w-5 h-5 text-gold shrink-0" />
              <div>
                <h4 className="text-sm font-semibold text-white">
                  Stage Inspector: {STAGES.find(s => s.id === selectedStageId)?.label}
                </h4>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Node Asset: <strong className="text-gray-300">{currentSelectionExecution.modelName}</strong> (ID: {currentSelectionExecution.modelId.toUpperCase()})
                </p>
              </div>
            </div>

            {/* Toggle tabs */}
            <div className="flex bg-dark-bg border border-dark-border rounded p-0.5 text-xs">
              <button
                onClick={() => setActiveTab("output")}
                className={`px-3 py-1 font-semibold rounded transition-all flex items-center gap-1 ${
                  activeTab === "output"
                    ? "bg-gold/10 text-gold border border-gold/10"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                <FileText className="w-3.5 h-3.5" /> Output File
              </button>
              
              {isPreviewable && (
                <button
                  onClick={() => setActiveTab("preview")}
                  className={`px-3 py-1 font-semibold rounded transition-all flex items-center gap-1 ${
                    activeTab === "preview"
                      ? "bg-gold/10 text-gold border border-gold/10"
                      : "text-gray-400 hover:text-white"
                  }`}
                  id="sandbox-tab-toggle"
                >
                  <Eye className="w-3.5 h-3.5" /> Live Sandbox
                </button>
              )}

              <button
                onClick={() => setActiveTab("logs")}
                className={`px-3 py-1 font-semibold rounded transition-all flex items-center gap-1 ${
                  activeTab === "logs"
                    ? "bg-gold/10 text-gold border border-gold/10"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                <Terminal className="w-3.5 h-3.5" /> System Logs
              </button>
            </div>
          </div>

          {/* Sub-Metric Bar if completed */}
          {currentSelectionExecution.status === "completed" && (
            <div className="px-6 py-2.5 bg-[#090909] border-b border-dark-border flex gap-6 text-[11px] font-mono text-gray-500">
              <span className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-gray-600" /> Duration: <strong className="text-gray-300">{(currentSelectionExecution.durationMs / 1000).toFixed(2)}s</strong>
              </span>
              <span className="flex items-center gap-1">
                <Database className="w-3.5 h-3.5 text-gray-600" /> Ingress/Egress: <strong className="text-gray-300">{currentSelectionExecution.tokensUsed} tokens</strong>
              </span>
              <span className="flex items-center gap-1">
                <Coins className="w-3.5 h-3.5 text-gray-600" /> Compute Charge: <strong className="text-gold">${currentSelectionExecution.cost.toFixed(6)}</strong>
              </span>
            </div>
          )}

          {/* Core Body content */}
          <div className={`${activeTab === "preview" ? "p-0" : "p-6"} min-h-[250px] max-h-[650px] overflow-y-auto bg-black/20`} id="inspector-body">
            {activeTab === "preview" && isPreviewable ? (
              <div className="w-full h-[550px] bg-dark-bg flex flex-col relative" id="sandbox-viewport-container">
                <div className="bg-[#05060b] border-b border-dark-border px-4 py-2 flex items-center justify-between text-xs font-mono text-gray-400 shrink-0 select-none">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    Interactive Sandbox Viewport
                  </span>
                  <span className="text-[10px] text-gray-500">sandbox_secured_env.sh</span>
                </div>
                <iframe
                  title="Pipeline Sandbox Output"
                  srcDoc={previewHtml || ""}
                  sandbox="allow-scripts allow-modals"
                  className="w-full flex-1 bg-[#0b0f19] border-0"
                  referrerPolicy="no-referrer"
                />
              </div>
            ) : activeTab === "output" ? (
              currentSelectionExecution.status === "completed" ? (
                <div className="space-y-4">
                  {selectedStageId === "review" && (
                    <div className="bg-gold/5 border border-gold/20 p-4 rounded text-xs leading-relaxed space-y-1">
                      <span className="font-serif text-gold font-bold uppercase tracking-wider block">Integrity Audit Passed</span>
                      Verified model separation is strictly enforced. Role segregation validated.
                    </div>
                  )}
                  <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed bg-[#050505] p-4 border border-dark-border rounded">
                    {currentSelectionExecution.output}
                  </pre>
                </div>
              ) : currentSelectionExecution.status === "blocked" ? (
                <div className="p-8 bg-red-950/5 border border-red-950/40 rounded flex flex-col items-center justify-center text-center space-y-3">
                  <ShieldAlert className="w-12 h-12 text-red-500" />
                  <div className="max-w-md space-y-1">
                    <h5 className="font-serif text-sm text-red-400 font-bold uppercase tracking-wider">
                      Workload Blocked by Security Protocol
                    </h5>
                    <p className="text-xs text-gray-400 leading-relaxed">
                      This stage was prevented from executing because the assigned Model Node is the author of this payload (Stage 02 or 03).
                    </p>
                    <p className="text-xs text-red-400 font-mono pt-2">
                      RULE: STICKY_AUTHOR_RESTRICT_FAIL
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-gray-500 italic flex items-center justify-center h-40">
                  This stage was skipped or is pending upstream completion.
                </div>
              )
            ) : (
              /* Logs Mode */
              <div className="font-mono text-[11px] text-gray-400 space-y-2 bg-[#050505] p-4 border border-dark-border rounded">
                {currentSelectionExecution.logs.map((logLine, lIdx) => (
                  <div key={lIdx} className="flex gap-2 items-start">
                    <span className="text-gray-600 shrink-0">[{lIdx + 1}]</span>
                    <span className={logLine.includes("[API_ERROR]") || logLine.includes("CRITICAL") ? "text-red-400" : logLine.includes("POLICY") || logLine.includes("Integrity") ? "text-gold font-medium" : "text-gray-300"}>
                      {logLine}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : isRunning ? (
        <div className="p-12 bg-dark-card border border-dark-border rounded flex flex-col items-center justify-center text-center space-y-4">
          <RefreshCw className="w-10 h-10 text-gold animate-spin" />
          <div className="space-y-1">
            <h4 className="text-xs font-bold font-mono text-gold uppercase tracking-wider animate-pulse">
              Running Stage {currentRunningStageIndex + 1}: {STAGES[currentRunningStageIndex]?.label}
            </h4>
            <p className="text-xs text-gray-500 max-w-sm leading-relaxed">
              Synthesizing prompt tensors, coordinating labor pool allocations, and evaluating integrity rules.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}
