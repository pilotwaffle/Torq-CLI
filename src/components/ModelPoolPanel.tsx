import React, { useState, useEffect, useRef } from "react";
import { ModelNode, NodeStatus } from "../types";
import { Plus, Edit2, Trash, Check, X, Shield, Cpu, RefreshCw, Terminal, ChevronDown, ChevronUp, AlertCircle, Play, Ban } from "lucide-react";

interface ModelPoolPanelProps {
  models: ModelNode[];
  onUpdateModels: (updated: ModelNode[]) => void;
  onTriggerRun?: (prompt: string, assignments: Record<string, string>, mode: "auto_substitute" | "strict_block") => void;
  forceSimulate?: boolean;
  onToggleForceSimulate?: (val: boolean) => void;
  onClearRun?: () => void;
  historyCount?: number;
  isRunning?: boolean;
  hasApiKey?: boolean;
}

const TorqLogo = () => {
  // Generate 24 radiating rays behind the disc for a high-tech aura
  const rayCount = 24;
  const rays = Array.from({ length: rayCount }).map((_, i) => {
    const angle = (i * 360) / rayCount * (Math.PI / 180);
    const r1 = 30;
    const r2 = 46;
    const x1 = 80 + r1 * Math.cos(angle);
    const y1 = 55 + r1 * Math.sin(angle);
    const x2 = 80 + r2 * Math.cos(angle);
    const y2 = 55 + r2 * Math.sin(angle);
    return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#f43f5e" className="text-rose-500/10 opacity-30" strokeWidth="0.5" />;
  });

  return (
    <svg viewBox="0 0 160 142" className="w-full max-w-[170px] flex-shrink-0" id="torq-premium-logo-svg">
      <defs>
        {/* Sleek metallic red gradient matching the polished look */}
        <linearGradient id="torqRedGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#ff416c" />
          <stop offset="40%" stopColor="#de1b41" />
          <stop offset="85%" stopColor="#9a0826" />
          <stop offset="100%" stopColor="#4f0312" />
        </linearGradient>

        {/* 3D background plate gradient */}
        <radialGradient id="plateGrad" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#222227" />
          <stop offset="75%" stopColor="#121215" />
          <stop offset="100%" stopColor="#0a0a0c" />
        </radialGradient>
      </defs>

      {/* Radiating precise thin lines */}
      <g>{rays}</g>

      {/* Dark metallic backing circle plate */}
      <circle cx="80" cy="55" r="33" fill="url(#plateGrad)" stroke="#27272a" strokeWidth="1" />
      <circle cx="80" cy="55" r="31.5" fill="none" stroke="#3f3f46" strokeWidth="0.5" className="opacity-60" />

      {/* Futuristic split double-T emblem (Left Stem) */}
      <path
        d="M 77,37 H 53 L 57,44 H 66 V 61 L 75,68 V 44 H 77 Z"
        fill="url(#torqRedGrad)"
        stroke="#4a000e"
        strokeWidth="0.5"
      />

      {/* Futuristic split double-T emblem (Right Stem) */}
      <path
        d="M 83,37 H 107 L 103,44 H 94 V 61 L 85,68 V 44 H 83 Z"
        fill="url(#torqRedGrad)"
        stroke="#4a000e"
        strokeWidth="0.5"
      />

      {/* Clean high-contrast typography below */}
      <text
        x="80"
        y="112"
        textAnchor="middle"
        className="font-sans font-extrabold tracking-[0.16em]"
        fontSize="22"
        fill="#e11d48"
        style={{ filter: "drop-shadow(0px 0px 1px rgba(225, 29, 72, 0.5))" }}
      >
        TORQ
      </text>

      <text
        x="80"
        y="131"
        textAnchor="middle"
        className="font-sans font-bold tracking-[0.28em]"
        fontSize="11"
        fill="#94a3b8"
      >
        CONSOLE
      </text>
    </svg>
  );
};

export default function ModelPoolPanel({
  models,
  onUpdateModels,
  onTriggerRun,
  forceSimulate = false,
  onToggleForceSimulate,
  onClearRun,
  historyCount = 0,
  isRunning = false,
  hasApiKey = false,
}: ModelPoolPanelProps) {
  const [isAdding, setIsAdding] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // CLI state
  const [cliLogs, setCliLogs] = useState<string[]>([
    "TORQ CONSOLE [Version 1.4.2]",
    "(c) 2026 TorqBusiness. Core Engine Online.",
    "Type 'help' to audit system commands.",
    "",
    "torq@orchestrator:~$ telemetry initialized ok."
  ]);
  const [cliInput, setCliInput] = useState("");
  const [isCliOpen, setIsCliOpen] = useState(true);
  const cliScrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll CLI logs to bottom
  useEffect(() => {
    if (cliScrollRef.current) {
      cliScrollRef.current.scrollTop = cliScrollRef.current.scrollHeight;
    }
  }, [cliLogs, isCliOpen]);

  // Form states for Add/Edit
  const [formName, setFormName] = useState("");
  const [formProvider, setFormProvider] = useState("");
  const [formRole, setFormRole] = useState("");
  const [formCost, setFormCost] = useState(10);
  const [formStatus, setFormStatus] = useState<NodeStatus>(NodeStatus.Active);
  const [formDesc, setFormDesc] = useState("");

  const handleStartAdd = () => {
    setFormName("");
    setFormProvider("");
    setFormRole("");
    setFormCost(12);
    setFormStatus(NodeStatus.Active);
    setFormDesc("");
    setIsAdding(true);
    setEditingId(null);
  };

  const handleStartEdit = (node: ModelNode) => {
    setFormName(node.name);
    setFormProvider(node.provider);
    setFormRole(node.role);
    setFormCost(node.costPerHr);
    setFormStatus(node.status);
    setFormDesc(node.description);
    setEditingId(node.id);
    setIsAdding(false);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim()) return;

    if (editingId) {
      // Editing
      const updated = models.map((m) => {
        if (m.id === editingId) {
          return {
            ...m,
            name: formName,
            provider: formProvider || "Custom Provider",
            role: formRole || "Generalist",
            costPerHr: Number(formCost),
            status: formStatus,
            description: formDesc,
          };
        }
        return m;
      });
      onUpdateModels(updated);
      setEditingId(null);
    } else {
      // Adding new
      const newNode: ModelNode = {
        id: "node-" + Math.random().toString(36).substring(2, 7),
        name: formName,
        provider: formProvider || "Custom Provider",
        role: formRole || "Generalist",
        costPerHr: Number(formCost),
        status: formStatus,
        description: formDesc || "User-defined custom intelligence agent.",
      };
      onUpdateModels([...models, newNode]);
      setIsAdding(false);
    }
  };

  const handleDelete = (id: string) => {
    if (confirm("Are you sure you want to retire this model node from the labor pool?")) {
      onUpdateModels(models.filter((m) => m.id !== id));
    }
  };

  const toggleStatus = (id: string) => {
    const updated = models.map((m) => {
      if (m.id === id) {
        let nextStatus = NodeStatus.Active;
        if (m.status === NodeStatus.Active) nextStatus = NodeStatus.Idle;
        else if (m.status === NodeStatus.Idle) nextStatus = NodeStatus.Offline;
        return { ...m, status: nextStatus };
      }
      return m;
    });
    onUpdateModels(updated);
  };

  const handleCliSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = cliInput.trim();
    if (!cmd) return;

    const newLogs = [...cliLogs, `torq@orchestrator:~$ ${cmd}`];
    const args = cmd.split(" ");
    const command = args[0].toLowerCase();

    switch (command) {
      case "help":
      case "?":
        newLogs.push(
          "Available CLI commands:",
          "  help / ?          - List available directives",
          "  status            - Print telemetry indicators",
          "  run <prompt>      - Fire secure model pipeline",
          "  simulate <on/off> - Override live API state",
          "  add <name> <role> - Quick-provision active node",
          "  clear             - Flush console screen buffer"
        );
        break;

      case "status":
        const activeNodes = models.filter(m => m.status === NodeStatus.Active);
        newLogs.push(
          "--- TELEMETRY LEDGER ---",
          `  Labor Pool size:  ${models.length} nodes`,
          `  Active Nodes:     ${activeNodes.length} operational`,
          `  Engine:           ${forceSimulate ? "LOCAL_SIMULATOR_PROXY" : "LIVE_GEMINI_CLOUD"}`,
          `  Key Configured:   ${hasApiKey ? "YES" : "NO"}`
        );
        break;

      case "clear":
        setCliLogs([]);
        setCliInput("");
        return;

      case "simulate":
        if (args[1] === "on" || args[1] === "1") {
          if (onToggleForceSimulate) onToggleForceSimulate(true);
          newLogs.push(">> System Mode set to [LOCAL_SIMULATOR_PROXY].");
        } else if (args[1] === "off" || args[1] === "0") {
          if (!hasApiKey) {
            newLogs.push(">> ERROR: Cannot set engine to live. No valid GEMINI_API_KEY found.");
          } else {
            if (onToggleForceSimulate) onToggleForceSimulate(false);
            newLogs.push(">> System Mode set to [LIVE_GEMINI_CLOUD].");
          }
        } else {
          newLogs.push("Usage: simulate <on/off>");
        }
        break;

      case "add":
        const name = args.slice(1, args.length - 1).join(" ") || args[1];
        const role = args[args.length - 1];
        if (!name || !role) {
          newLogs.push("Usage: add <NodeName> <Role>");
          newLogs.push("Example: add GPT-5 FastRefiner");
        } else {
          const newNode: ModelNode = {
            id: "node-" + Math.random().toString(36).substring(2, 7),
            name: name,
            provider: "CLI Agent Node",
            role: role,
            costPerHr: 14.50,
            status: NodeStatus.Active,
            description: "Quick-provisioned via the TORQ Console CLI."
          };
          onUpdateModels([...models, newNode]);
          newLogs.push(`>> Provisioned [${name}] into active duty.`);
        }
        break;

      case "run":
        const promptText = args.slice(1).join(" ");
        if (!promptText) {
          newLogs.push("Usage: run <prompt text>");
        } else if (isRunning) {
          newLogs.push(">> ERROR: Run registers currently busy executing a pipeline.");
        } else if (onTriggerRun) {
          const assignments: Record<string, string> = {};
          const activeIds = models.filter(m => m.status === NodeStatus.Active).map(m => m.id);
          
          if (activeIds.length === 0) {
            newLogs.push(">> ERROR: No active nodes in labor pool.");
          } else {
            const stagesList = ["init", "generate", "refine", "review", "export"];
            stagesList.forEach((stg, index) => {
              assignments[stg] = activeIds[index % activeIds.length];
            });

            onTriggerRun(promptText, assignments, "auto_substitute");
            newLogs.push(`>> Triggering pipeline execution: "${promptText}"`);
            newLogs.push(">> Switch to Orchestrator to monitor.");
          }
        } else {
          newLogs.push(">> ERROR: Execution engine offline.");
        }
        break;

      default:
        newLogs.push(`Command unrecognized: '${command}'. Type 'help' for options.`);
    }

    setCliLogs(newLogs);
    setCliInput("");
  };

  const activeCount = models.filter((m) => m.status === NodeStatus.Active).length;

  return (
    <aside className="w-80 bg-dark-sidebar border-r border-dark-border flex flex-col h-full overflow-hidden shrink-0" id="model-pool-panel">
      {/* TORQ CONSOLE BRAND HEADER */}
      <div className="flex justify-center items-center py-5 border-b border-dark-border bg-black/40 animate-fade-in" id="torq-logo-container">
        <TorqLogo />
      </div>

      {/* INTERACTIVE CLI COMPONENT */}
      <div className="border-b border-dark-border bg-black/25 flex flex-col" id="torq-cli-container">
        <div 
          onClick={() => setIsCliOpen(!isCliOpen)}
          className="px-5 py-2.5 flex items-center justify-between text-xs font-mono text-gray-400 hover:text-gold cursor-pointer transition-all select-none bg-dark-sidebar/60 border-b border-dark-border/40"
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-gold shrink-0 animate-pulse" />
            <span className="text-[10px] tracking-wide text-gray-300">TORQ-CLI-SHELL.EXE</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[9px] text-emerald-500 bg-emerald-500/10 px-1 py-0.2 rounded border border-emerald-500/20 font-bold uppercase tracking-wider">ONLINE</span>
            {isCliOpen ? <ChevronUp className="w-3.5 h-3.5 text-gray-500" /> : <ChevronDown className="w-3.5 h-3.5 text-gray-500" />}
          </div>
        </div>

        {isCliOpen && (
          <div className="p-4 bg-black/95 flex flex-col h-40 animate-fade-in" id="cli-viewport-wrapper">
            <div 
              ref={cliScrollRef}
              className="flex-1 overflow-y-auto space-y-1 font-mono text-[10px] text-amber-500/90 leading-relaxed pr-1 scrollbar-thin"
              id="cli-logs-container"
            >
              {cliLogs.map((log, idx) => (
                <div key={idx} className="whitespace-pre-wrap">
                  {log.startsWith("torq@orchestrator") ? (
                    <span className="text-emerald-400">{log}</span>
                  ) : log.startsWith(">> ERROR") ? (
                    <span className="text-red-400">{log}</span>
                  ) : log.startsWith(">>") || log.startsWith("[") || log.startsWith("---") ? (
                    <span className="text-gold font-semibold">{log}</span>
                  ) : (
                    log
                  )}
                </div>
              ))}
            </div>

            <form onSubmit={handleCliSubmit} className="mt-2 flex items-center border-t border-dark-border/50 pt-2 shrink-0">
              <span className="font-mono text-[10px] text-emerald-400 mr-1.5 shrink-0 select-none">torq@cli:~$</span>
              <input
                type="text"
                placeholder="Type 'help'..."
                value={cliInput}
                onChange={(e) => setCliInput(e.target.value)}
                className="flex-1 min-w-0 bg-transparent text-gray-200 font-mono text-[10px] focus:outline-none placeholder-gray-700"
                id="cli-text-input"
              />
              <div className="w-1.5 h-3.5 bg-emerald-400 animate-pulse shrink-0 ml-1" />
            </form>
          </div>
        )}
      </div>

      {/* Header */}
      <div className="p-6 border-b border-dark-border bg-dark-sidebar/20" id="panel-header">
        <div className="flex items-center justify-between mb-2">
          <h2 className="font-serif text-base tracking-wide text-gold flex items-center gap-2">
            <Cpu className="w-4 h-4" /> Labor Pool
          </h2>
          <button
            onClick={handleStartAdd}
            className="p-1 rounded-sm border border-dark-border bg-dark-card hover:border-gold text-gold transition-colors text-xs flex items-center gap-1 px-2 py-1"
            title="Provision New Model Node"
            id="add-node-btn"
          >
            <Plus className="w-3.5 h-3.5" /> Provision
          </button>
        </div>
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Managed Paid Instances</span>
          <span className="font-mono text-[10px] bg-dark-card px-1.5 py-0.5 rounded border border-dark-border">
            {activeCount}/{models.length} ONLINE
          </span>
        </div>
      </div>

      {/* Main Form or List container */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3" id="nodes-container">
        {isAdding || editingId ? (
          <form onSubmit={handleSave} className="bg-dark-card border border-gold/30 rounded p-4 space-y-3 animate-fade-in" id="node-form">
            <div className="flex items-center justify-between border-b border-dark-border pb-2">
              <h3 className="text-xs font-semibold text-gold tracking-wider uppercase">
                {editingId ? "Edit Model Node" : "Provision New Node"}
              </h3>
              <button
                type="button"
                onClick={() => {
                  setIsAdding(false);
                  setEditingId(null);
                }}
                className="text-gray-500 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Model Name</label>
              <input
                type="text"
                required
                placeholder="e.g. GPT-4o"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Intelligence Provider</label>
              <input
                type="text"
                placeholder="e.g. OpenAI Paid Node"
                value={formProvider}
                onChange={(e) => setFormProvider(e.target.value)}
                className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Role Specialty</label>
                <input
                  type="text"
                  placeholder="e.g. Fast Generator"
                  value={formRole}
                  onChange={(e) => setFormRole(e.target.value)}
                  className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Cost per Hour ($)</label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  required
                  value={formCost}
                  onChange={(e) => setFormCost(Number(e.target.value))}
                  className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Instance Status</label>
              <select
                value={formStatus}
                onChange={(e) => setFormStatus(e.target.value as NodeStatus)}
                className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none"
              >
                <option value={NodeStatus.Active}>Active (Available)</option>
                <option value={NodeStatus.Idle}>Idle (Standby)</option>
                <option value={NodeStatus.Offline}>Offline (Paused)</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-gray-500 uppercase tracking-wider block">Capabilities Blurb</label>
              <textarea
                placeholder="Describe model strengths..."
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
                rows={2}
                className="w-full text-xs bg-dark-bg border border-dark-border text-white px-2 py-1.5 rounded focus:border-gold focus:outline-none resize-none"
              />
            </div>

            <button
              type="submit"
              className="w-full bg-gold hover:bg-gold-hover text-dark-bg font-medium py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-1"
            >
              <Check className="w-3.5 h-3.5" /> Save Configuration
            </button>
          </form>
        ) : null}

        {models.map((node) => {
          const isNodeActive = node.status === NodeStatus.Active;
          const isNodeIdle = node.status === NodeStatus.Idle;
          const isNodeOffline = node.status === NodeStatus.Offline;

          return (
            <div
              key={node.id}
              className={`p-3 bg-dark-card border border-dark-border rounded hover:border-gold/40 transition-all ${
                isNodeOffline ? "opacity-40" : ""
              }`}
              id={`node-card-${node.id}`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="text-[10px] text-gray-500 font-mono block uppercase tracking-wider">
                    {node.provider}
                  </span>
                  <h4 className="text-sm font-semibold text-gray-200 mt-0.5">{node.name}</h4>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleStartEdit(node)}
                    className="p-1 rounded text-gray-500 hover:text-gold hover:bg-dark-bg transition-all"
                    title="Edit Node Details"
                  >
                    <Edit2 className="w-3 h-3" />
                  </button>
                  {models.length > 3 ? (
                    <button
                      onClick={() => handleDelete(node.id)}
                      className="p-1 rounded text-gray-500 hover:text-red-500 hover:bg-dark-bg transition-all"
                      title="Deprovision Node"
                    >
                      <Trash className="w-3 h-3" />
                    </button>
                  ) : null}
                </div>
              </div>

              <div className="mt-2 flex items-center justify-between border-t border-dark-border/40 pt-2 text-xs">
                <span className="text-gray-400 font-mono text-[10px]">{node.role}</span>
                <span className="text-gold font-mono text-[11px] font-medium">
                  ${node.costPerHr.toFixed(2)}/hr
                </span>
              </div>

              <p className="text-[11px] text-gray-500 mt-1.5 leading-relaxed italic line-clamp-2">
                {node.description}
              </p>

              <div className="mt-2.5 flex items-center justify-between">
                <span className="font-mono text-[9px] text-gray-600">ID: {node.id.toUpperCase()}</span>
                
                {/* Status Toggler */}
                <button
                  onClick={() => toggleStatus(node.id)}
                  className={`px-2 py-0.5 rounded-full text-[9px] font-bold tracking-wider uppercase transition-all ${
                    isNodeActive
                      ? "bg-gold/10 text-gold border border-gold/30 hover:bg-gold/20"
                      : isNodeIdle
                      ? "bg-amber-500/10 text-amber-500 border border-amber-500/20 hover:bg-amber-500/20"
                      : "bg-gray-800 text-gray-500 border border-gray-700 hover:bg-gray-700"
                  }`}
                  title="Click to cycle status"
                >
                  {node.status}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-auto p-4 border-t border-dark-border bg-black/40 text-[10px] text-gray-600 font-mono tracking-wider flex items-center justify-between">
        <span>© 2026 STRICT LABOR POOL</span>
        <div className="flex items-center gap-1.5 text-gold">
          <Shield className="w-3 h-3 animate-pulse" /> ROLE_SEGREGATION_ON
        </div>
      </div>
    </aside>
  );
}
