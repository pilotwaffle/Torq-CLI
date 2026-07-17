import React, { useState, useEffect } from "react";
import { ModelNode, NodeStatus } from "../types";
import { Sparkles, AlertTriangle, Play, HelpCircle, Lock, Unlock, RefreshCw } from "lucide-react";

interface PipelineSetupProps {
  models: ModelNode[];
  onTriggerRun: (prompt: string, assignments: Record<string, string>, mode: "auto_substitute" | "strict_block") => void;
  isRunning: boolean;
  onClearRun: () => void;
  forceSimulate: boolean;
  onToggleForceSimulate: (val: boolean) => void;
  hasApiKey: boolean;
}

const PRESET_PROMPTS = [
  {
    title: "SQL Schema & Execution Cache",
    text: "Design a high-throughput PostgreSQL database schema for a globally distributed rideshare platform. Include table definitions, proper indexing, foreign key constraints, and write an optimized query to calculate the average driver rating per city dynamically."
  },
  {
    title: "Cybersecurity Threat Assessment",
    text: "Conduct an analysis on a theoretical breach vector: an attacker compromises a server via a dependency vulnerability, then attempts privilege escalation. Write a security log audit report and a robust script in Python to identify anomalous administrative actions in standard auth log files."
  },
  {
    title: "Luxury Brand Copywriting",
    text: "Compose highly engaging, sophisticated product copy for a premium, celestial-themed automatic watch called 'Chronos Cosmos'. Highlight Swiss precision, astronomical tracking, titanium casing, and draw a poetic parallel between the rotation of stars and mechanical gears."
  },
  {
    title: "Interactive 3D CAD Lens Case",
    text: "Generate a fully interactive 3D WebGL model of a double-well contact lens case with embossed Left (L) and Right (R) caps. Support custom rotation, ambient neon lighting, click-to-open hinge telemetry, and robust design review checks."
  }
];

export default function PipelineSetup({
  models,
  onTriggerRun,
  isRunning,
  onClearRun,
  forceSimulate,
  onToggleForceSimulate,
  hasApiKey
}: PipelineSetupProps) {
  const [prompt, setPrompt] = useState(PRESET_PROMPTS[0].text);
  const [assignments, setAssignments] = useState<Record<string, string>>({
    generate: "",
    refine: "",
    review: "",
    export: "",
  });
  const [enforcementMode, setEnforcementMode] = useState<"auto_substitute" | "strict_block">("auto_substitute");

  const activeModels = models.filter((m) => m.status === NodeStatus.Active);

  // Initialize assignments with first active models
  useEffect(() => {
    if (activeModels.length > 0) {
      setAssignments((prev) => {
        // Try to stagger defaults to avoid immediate conflicts
        const gen = activeModels[0]?.id || "";
        const ref = activeModels[1]?.id || activeModels[0]?.id || "";
        // Put a different one for review if possible
        const rev = activeModels[2]?.id || activeModels[1]?.id || activeModels[0]?.id || "";
        const exp = activeModels[3]?.id || activeModels[0]?.id || "";
        
        return {
          generate: prev.generate && activeModels.some(m => m.id === prev.generate) ? prev.generate : gen,
          refine: prev.refine && activeModels.some(m => m.id === prev.refine) ? prev.refine : ref,
          review: prev.review && activeModels.some(m => m.id === prev.review) ? prev.review : rev,
          export: prev.export && activeModels.some(m => m.id === prev.export) ? prev.export : exp,
        };
      });
    }
  }, [models]);

  const handleAssignmentChange = (stageId: string, modelId: string) => {
    setAssignments((prev) => ({
      ...prev,
      [stageId]: modelId,
    }));
  };

  // Check conflicts
  const hasGenerateConflict = assignments.review !== "" && assignments.review === assignments.generate;
  const hasRefineConflict = assignments.review !== "" && assignments.review === assignments.refine;
  const hasConflict = hasGenerateConflict || hasRefineConflict;

  const handleRun = () => {
    if (isRunning) return;
    if (hasConflict && enforcementMode === "strict_block") return;
    onTriggerRun(prompt, assignments, enforcementMode);
  };

  const getModelName = (id: string) => {
    const m = models.find((x) => x.id === id);
    return m ? m.name : "System Kernel";
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded p-6 shadow-xl space-y-6" id="pipeline-setup">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-dark-border pb-4 gap-4">
        <div>
          <h3 className="font-serif text-lg text-gold tracking-wide">Configure Pipeline</h3>
          <p className="text-xs text-gray-500 mt-1">Assign model nodes and define integrity rules for execution</p>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          {/* Engine Mode Toggle */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400 font-medium">Engine Mode:</span>
            <div className="flex border border-dark-border rounded p-0.5 bg-dark-bg">
              <button
                type="button"
                onClick={() => onToggleForceSimulate(false)}
                disabled={!hasApiKey}
                className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider rounded transition-all flex items-center gap-1 ${
                  !forceSimulate && hasApiKey
                    ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                    : "text-gray-500 hover:text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed"
                }`}
                title={hasApiKey ? "Execute via Live Google Gemini API" : "Live API key missing in Secrets panel"}
              >
                Live Cloud
              </button>
              <button
                type="button"
                onClick={() => onToggleForceSimulate(true)}
                className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider rounded transition-all flex items-center gap-1 ${
                  forceSimulate || !hasApiKey
                    ? "bg-gold/15 text-gold border border-gold/30"
                    : "text-gray-500 hover:text-gray-300"
                }`}
                title="Execute via high-speed simulated proxy node"
              >
                Simulated
              </button>
            </div>
          </div>

          {/* Policy Guard */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400 font-medium">Policy Guard:</span>
            <div className="flex border border-dark-border rounded p-0.5 bg-dark-bg">
              <button
                type="button"
                onClick={() => setEnforcementMode("auto_substitute")}
                className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider rounded transition-all flex items-center gap-1 ${
                  enforcementMode === "auto_substitute"
                    ? "bg-gold/15 text-gold border border-gold/30"
                    : "text-gray-500 hover:text-gray-300"
                }`}
                title="Automatically swap reviews to resolve author conflicts"
              >
                <Unlock className="w-3 h-3" /> Auto-Swap
              </button>
              <button
                type="button"
                onClick={() => setEnforcementMode("strict_block")}
                className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider rounded transition-all flex items-center gap-1 ${
                  enforcementMode === "strict_block"
                    ? "bg-red-500/15 text-red-400 border border-red-500/30"
                    : "text-gray-500 hover:text-gray-300"
                }`}
                title="Refuse to launch pipeline if conflicts exist"
              >
                <Lock className="w-3 h-3" /> Strict Block
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Prompt Selection */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <span className="text-xs font-bold text-gold uppercase tracking-wider block">
              Workload Prompt & PRD Input
            </span>
            <p className="text-[11px] text-gray-500 mt-0.5">
              Enter your app idea, raw requirements, or paste a full Product Requirement Document (PRD) below.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {PRESET_PROMPTS.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setPrompt(preset.text)}
                className={`text-[10px] font-medium px-2.5 py-1 rounded border transition-all ${
                  prompt === preset.text
                    ? "bg-gold/10 text-gold border-gold/40 font-semibold shadow-inner"
                    : "bg-dark-bg text-gray-400 border-dark-border hover:text-gray-300"
                }`}
              >
                Use Preset {idx + 1}: {preset.title}
              </button>
            ))}
          </div>
        </div>

        <textarea
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          rows={5}
          placeholder="Type your application idea, prompt instructions, or paste a full PRD here... (e.g. 'Build a secure medical patient portal with custom role-segregation and real-time biometric feeds...')"
          className="w-full text-sm bg-dark-bg border border-dark-border/80 text-white p-4 rounded focus:border-gold focus:ring-1 focus:ring-gold/30 focus:outline-none resize-y leading-relaxed font-sans placeholder-gray-600 transition-all"
          disabled={isRunning}
          id="workload-prompt-input"
        />
      </div>

      {/* Node Assignment Stage Walkthrough */}
      <div className="space-y-3">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
          Role-to-Stage Mapping
        </span>
        
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {/* Stage 1: Init */}
          <div className="p-3 bg-dark-bg border border-dark-border/40 rounded flex flex-col justify-between">
            <div>
              <span className="text-[9px] font-mono text-gray-500 block uppercase">Stage 01</span>
              <h4 className="text-xs font-bold text-gray-300 mt-0.5">Initialization</h4>
              <p className="text-[10px] text-gray-500 mt-1">Prepares workspace & instructions.</p>
            </div>
            <div className="mt-4 pt-2 border-t border-dark-border/40 text-[11px] text-gray-400 font-mono italic">
              System Kernel
            </div>
          </div>

          {/* Stage 2: Generate */}
          <div className={`p-3 bg-dark-bg border rounded flex flex-col justify-between transition-all ${
            hasGenerateConflict ? "border-red-500/20 bg-red-950/5" : "border-dark-border"
          }`}>
            <div>
              <span className="text-[9px] font-mono text-gray-500 block uppercase">Stage 02</span>
              <h4 className="text-xs font-bold text-gray-300 mt-0.5">02. Generate</h4>
              <p className="text-[10px] text-gray-500 mt-1">Drafts initial codebase or output.</p>
            </div>
            <select
              value={assignments.generate}
              onChange={(e) => handleAssignmentChange("generate", e.target.value)}
              className="mt-3 text-xs bg-dark-card border border-dark-border rounded px-2 py-1 text-gray-300 focus:border-gold focus:outline-none"
              disabled={isRunning || activeModels.length === 0}
            >
              {activeModels.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
              {activeModels.length === 0 && <option value="">No Active Nodes</option>}
            </select>
          </div>

          {/* Stage 3: Refine */}
          <div className={`p-3 bg-dark-bg border rounded flex flex-col justify-between transition-all ${
            hasRefineConflict ? "border-red-500/20 bg-red-950/5" : "border-dark-border"
          }`}>
            <div>
              <span className="text-[9px] font-mono text-gray-500 block uppercase">Stage 03</span>
              <h4 className="text-xs font-bold text-gray-300 mt-0.5">03. Refine</h4>
              <p className="text-[10px] text-gray-500 mt-1">Optimizes logic and files.</p>
            </div>
            <select
              value={assignments.refine}
              onChange={(e) => handleAssignmentChange("refine", e.target.value)}
              className="mt-3 text-xs bg-dark-card border border-dark-border rounded px-2 py-1 text-gray-300 focus:border-gold focus:outline-none"
              disabled={isRunning || activeModels.length === 0}
            >
              {activeModels.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
              {activeModels.length === 0 && <option value="">No Active Nodes</option>}
            </select>
          </div>

          {/* Stage 4: Review */}
          <div className={`p-3 bg-dark-bg border rounded flex flex-col justify-between transition-all ${
            hasConflict 
              ? "border-red-500 bg-red-950/10" 
              : "border-dark-border"
          }`}>
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono text-gray-500 block uppercase">Stage 04</span>
                {hasConflict && <AlertTriangle className="w-3.5 h-3.5 text-red-500 animate-pulse" />}
              </div>
              <h4 className={`text-xs font-bold mt-0.5 ${hasConflict ? "text-red-400" : "text-gray-300"}`}>
                04. Review
              </h4>
              <p className="text-[10px] text-gray-500 mt-1">Audits output for integrity violations.</p>
            </div>
            <select
              value={assignments.review}
              onChange={(e) => handleAssignmentChange("review", e.target.value)}
              className={`mt-3 text-xs bg-dark-card border rounded px-2 py-1 focus:outline-none ${
                hasConflict 
                  ? "border-red-500 text-red-400 focus:border-red-500" 
                  : "border-dark-border text-gray-300 focus:border-gold"
              }`}
              disabled={isRunning || activeModels.length === 0}
            >
              {activeModels.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
              {activeModels.length === 0 && <option value="">No Active Nodes</option>}
            </select>
          </div>

          {/* Stage 5: Export */}
          <div className="p-3 bg-dark-bg border border-dark-border rounded flex flex-col justify-between">
            <div>
              <span className="text-[9px] font-mono text-gray-500 block uppercase">Stage 05</span>
              <h4 className="text-xs font-bold text-gray-300 mt-0.5">05. Export</h4>
              <p className="text-[10px] text-gray-500 mt-1">Delivers verified output packaging.</p>
            </div>
            <select
              value={assignments.export}
              onChange={(e) => handleAssignmentChange("export", e.target.value)}
              className="mt-3 text-xs bg-dark-card border border-dark-border rounded px-2 py-1 text-gray-300 focus:border-gold focus:outline-none"
              disabled={isRunning || activeModels.length === 0}
            >
              <option value="system">System Kernel</option>
              {activeModels.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Warnings & Integrity Action Info */}
      {hasConflict ? (
        <div className="bg-red-500/5 border border-red-500/20 rounded p-4 flex gap-3 animate-fade-in" id="conflict-alert">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h5 className="text-xs font-bold text-red-400 uppercase tracking-wider">
              Integrity Breach: Author Is Reviewing Self
            </h5>
            <p className="text-xs text-gray-400 leading-relaxed">
              Model node <strong className="text-white">{getModelName(assignments.review)}</strong> is assigned to authorship in Stage 
              {hasGenerateConflict && hasRefineConflict ? " 02 & 03" : hasGenerateConflict ? " 02 (Generate)" : " 03 (Refine)"} and Stage 04 (Review).
            </p>
            <div className="pt-2">
              {enforcementMode === "strict_block" ? (
                <span className="inline-block text-[10px] font-mono bg-red-500/10 text-red-400 px-2 py-0.5 border border-red-500/30 rounded uppercase font-bold tracking-wider">
                  STATUS: PIPELINE BLOCKED — Correct Stage assignments to unlock run.
                </span>
              ) : (
                <span className="inline-block text-[10px] font-mono bg-amber-500/10 text-amber-500 px-2 py-0.5 border border-amber-500/30 rounded uppercase font-bold tracking-wider">
                  STATUS: ENFORCEMENT RESOLUTION ARMED — System will dynamically substitute a backup node on launch.
                </span>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded p-4 flex gap-3 text-emerald-400/90 text-xs leading-relaxed" id="security-cleared">
          <CheckCircle className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold uppercase tracking-wider block text-emerald-400 mb-0.5">Integrity Protocols Verified</span>
            Role segregation fully enforced. Stage 04 is isolated from Stage 02 and Stage 03 authorship. Ready for production run.
          </div>
        </div>
      )}

      {/* Button Run */}
      <div className="flex items-center justify-end gap-3 pt-2">
        {isRunning ? (
          <button
            type="button"
            className="px-6 py-2 bg-dark-bg border border-dark-border text-gray-500 rounded text-xs flex items-center gap-2 cursor-not-allowed font-medium font-mono"
          >
            <RefreshCw className="w-4.5 h-4.5 animate-spin" /> PIPELINE_BUSY_EXEC
          </button>
        ) : (
          <button
            type="button"
            onClick={handleRun}
            disabled={hasConflict && enforcementMode === "strict_block"}
            className={`px-6 py-2 rounded text-xs font-semibold tracking-wide transition-all duration-300 flex items-center gap-2 ${
              hasConflict && enforcementMode === "strict_block"
                ? "bg-gray-800 text-gray-600 border border-gray-700 cursor-not-allowed"
                : "bg-gold hover:bg-gold-hover text-dark-bg shadow-lg cursor-pointer transform hover:-translate-y-0.5"
            }`}
            id="run-pipeline-btn"
          >
            <Play className="w-4 h-4 fill-current" /> RUN MODEL WORKLOAD
          </button>
        )}
      </div>
    </div>
  );
}

function CheckCircle(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
