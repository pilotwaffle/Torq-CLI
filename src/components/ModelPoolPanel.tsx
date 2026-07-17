import React, { useState } from "react";
import { ModelNode, NodeStatus } from "../types";
import { Plus, Edit2, Trash, Check, X, Shield, Cpu, RefreshCw } from "lucide-react";

interface ModelPoolPanelProps {
  models: ModelNode[];
  onUpdateModels: (updated: ModelNode[]) => void;
}

export default function ModelPoolPanel({ models, onUpdateModels }: ModelPoolPanelProps) {
  const [isAdding, setIsAdding] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

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

  const activeCount = models.filter((m) => m.status === NodeStatus.Active).length;

  return (
    <aside className="w-80 bg-dark-sidebar border-r border-dark-border flex flex-col h-full overflow-hidden shrink-0" id="model-pool-panel">
      {/* Header */}
      <div className="p-6 border-b border-dark-border" id="panel-header">
        <div className="flex items-center justify-between mb-2">
          <h2 className="font-serif text-xl tracking-wide text-gold flex items-center gap-2">
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
