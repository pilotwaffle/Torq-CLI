import React from "react";
import { PipelineRun, IntegrityLog, ModelNode, NodeStatus } from "../types";
import { ShieldCheck, ShieldAlert, FileWarning, Fingerprint, Lock, Layers, BarChart2 } from "lucide-react";

interface IntegrityReportProps {
  activeRun: PipelineRun | null;
  history: PipelineRun[];
  models: ModelNode[];
}

export default function IntegrityReport({ activeRun, history, models }: IntegrityReportProps) {
  // Aggregate stats
  const allRuns = [...(activeRun ? [activeRun] : []), ...history];
  const totalRuns = allRuns.length;
  
  const totalViolationsDetected = allRuns.reduce((acc, run) => {
    return acc + run.integrityLogs.filter(log => log.type === "conflict_detected").length;
  }, 0);

  const totalSubstitutionsEnforced = allRuns.reduce((acc, run) => {
    return acc + run.integrityLogs.filter(log => log.type === "substitution_enforced").length;
  }, 0);

  const totalStrictBlocksTriggered = allRuns.reduce((acc, run) => {
    return acc + (run.status === "blocked" ? 1 : 0);
  }, 0);

  // Collect all logs
  const allIntegrityLogs: { runTitle: string; log: IntegrityLog }[] = [];
  allRuns.forEach(run => {
    run.integrityLogs.forEach(log => {
      allIntegrityLogs.push({
        runTitle: run.title,
        log
      });
    });
  });

  // Sort logs by newest first
  allIntegrityLogs.sort((a, b) => new Date(b.log.timestamp).getTime() - new Date(a.log.timestamp).getTime());

  return (
    <div className="bg-dark-card border border-dark-border rounded p-6 shadow-xl space-y-6" id="integrity-report-panel">
      {/* Header */}
      <div className="border-b border-dark-border pb-4 flex items-center justify-between">
        <div>
          <h3 className="font-serif text-lg text-gold tracking-wide flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-gold" /> Security & Integrity Protocol
          </h3>
          <p className="text-xs text-gray-500 mt-1">Audit ledger, role segregation enforcement, and mathematical compliance</p>
        </div>
        <div className="text-[10px] font-mono text-gray-400 bg-dark-bg border border-dark-border px-3 py-1 rounded">
          PROTOCOL CFG: STICKY_AUTHOR_RESTRICT
        </div>
      </div>

      {/* Grid of integrity states */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4" id="integrity-stats-grid">
        <div className="bg-[#080808] border border-dark-border rounded p-4 text-center">
          <span className="text-[10px] text-gray-500 uppercase font-mono block">Compliant Runs</span>
          <span className="text-2xl font-mono text-emerald-400 mt-1 block">
            {totalRuns - totalStrictBlocksTriggered}
          </span>
          <span className="text-[9px] text-gray-600 block mt-1">100% policy clean</span>
        </div>

        <div className="bg-[#080808] border border-dark-border rounded p-4 text-center">
          <span className="text-[10px] text-gray-500 uppercase font-mono block">Conflicts Flagged</span>
          <span className="text-2xl font-mono text-red-400 mt-1 block">
            {totalViolationsDetected}
          </span>
          <span className="text-[9px] text-gray-600 block mt-1">Self-review attempts caught</span>
        </div>

        <div className="bg-[#080808] border border-dark-border rounded p-4 text-center">
          <span className="text-[10px] text-gray-500 uppercase font-mono block">Auto-Substitutions</span>
          <span className="text-2xl font-mono text-gold mt-1 block">
            {totalSubstitutionsEnforced}
          </span>
          <span className="text-[9px] text-gray-600 block mt-1">Enforced replacements</span>
        </div>

        <div className="bg-[#080808] border border-dark-border rounded p-4 text-center">
          <span className="text-[10px] text-gray-500 uppercase font-mono block">Strict Blocks Triggered</span>
          <span className="text-2xl font-mono text-red-500 mt-1 block">
            {totalStrictBlocksTriggered}
          </span>
          <span className="text-[9px] text-gray-600 block mt-1">Suspended workflows</span>
        </div>
      </div>

      {/* Logic Breakdown Box */}
      <div className="bg-dark-bg border border-dark-border rounded p-5 space-y-4" id="integrity-rulebook">
        <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
          <Lock className="w-4 h-4 text-gold" /> Isolation Theorem
        </h4>
        
        <div className="flex flex-col md:flex-row gap-6 items-center justify-between border-t border-b border-dark-border/40 py-4">
          <div className="space-y-1">
            <span className="text-xs text-gray-400 font-semibold">Strict Role Segregation</span>
            <p className="text-xs text-gray-500 leading-relaxed max-w-md">
              To guarantee objective validation and prevent positive feedback loops in cascading pipelines, any model instance serving as an Author (Generate or Refine stages) is mathematically forbidden from serving as the Peer Reviewer.
            </p>
          </div>

          <div className="bg-[#111] p-4 border border-dark-border rounded text-center font-mono text-xs select-none shadow-inner shrink-0">
            <div className="text-gray-500 text-[10px] mb-1">SET THEOREM SPEC</div>
            <div className="text-gold font-medium text-sm">
              Reviewer_Node ∩ &#123; Generator, Refiner &#125; = ∅
            </div>
            <div className="text-[9px] text-gray-600 mt-1.5 uppercase font-bold tracking-wider">
              Enforcement Protocol: Active
            </div>
          </div>
        </div>

        <div className="text-xs text-gray-400 leading-relaxed space-y-1">
          <span className="font-semibold text-gray-300 block mb-1">Enforcement Logic Matrix:</span>
          <ul className="list-disc pl-5 space-y-1 text-gray-500">
            <li>
              <strong className="text-gray-300">Strict Block Mode:</strong> The kernel refuses to initiate compiling or processing. Thread execution is paused.
            </li>
            <li>
              <strong className="text-gray-300">Auto-Swap Mode:</strong> The kernel detects violation, registers incident ID, reviews the active model pool, finds a secondary Active model node not involved in Stage 02 or 03, and injects it into Stage 04 prior to execution.
            </li>
          </ul>
        </div>
      </div>

      {/* Audit Log Timeline */}
      <div className="space-y-3" id="integrity-timeline">
        <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-gold" /> Security Ledger Timeline
        </h4>

        {allIntegrityLogs.length === 0 ? (
          <div className="p-8 border border-dashed border-dark-border rounded text-center text-xs text-gray-500 italic">
            No integrity violations have been recorded. System remains fully compliant.
          </div>
        ) : (
          <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1" id="logs-timeline-list">
            {allIntegrityLogs.map(({ runTitle, log }, idx) => {
              const isConflict = log.type === "conflict_detected";
              return (
                <div
                  key={idx}
                  className={`p-3 rounded border text-xs leading-relaxed flex items-start gap-3 transition-all ${
                    isConflict
                      ? "bg-red-500/5 border-red-500/20 text-red-300"
                      : "bg-gold/5 border-gold/20 text-gold"
                  }`}
                >
                  {isConflict ? (
                    <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                  ) : (
                    <ShieldCheck className="w-5 h-5 text-gold shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between font-mono text-[10px] text-gray-500">
                      <span>RUN: "{runTitle}"</span>
                      <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-gray-200">{log.message}</p>
                    <div className="flex items-center gap-4 text-[10px] font-mono text-gray-500 pt-1">
                      <span>STAGE: {log.stageId.toUpperCase()}</span>
                      {log.blockedNodeId && <span>BLOCKED NODE ID: {log.blockedNodeId.toUpperCase()}</span>}
                      {log.substitutedNodeId && <span className="text-gold font-bold">SUBSTITUTED WITH ID: {log.substitutedNodeId.toUpperCase()}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
