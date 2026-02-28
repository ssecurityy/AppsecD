"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft, FileText, Copy, Check, Download, Search, Eye } from "lucide-react";
import toast from "react-hot-toast";

function CopyBtn({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success(label || "Copied");
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy}
      className="p-1.5 rounded-lg transition-all text-xs"
      style={{ color: copied ? "var(--accent-green)" : "var(--text-muted)", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}
      title="Copy content">
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

export default function SecListsCategoryPage() {
  const params = useParams();
  const category = params.category as string;
  const { hydrate } = useAuthStore();
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [previewFile, setPreviewFile] = useState<any>(null);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (!category) return;
    const decoded = decodeURIComponent(category);
    api.seclistsFiles(decoded)
      .then(r => setFiles(r.files || []))
      .catch(() => setFiles([]))
      .finally(() => setLoading(false));
  }, [category]);

  const catName = decodeURIComponent(category).replace(/-/g, " ").replace(/_/g, " ");
  const formatSize = (bytes: number) =>
    bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

  const filtered = files.filter(f =>
    !search || f.path.toLowerCase().includes(search.toLowerCase()) || (f.filename || "").toLowerCase().includes(search.toLowerCase())
  );

  const handleDownload = async (f: any) => {
    if (!f.id) { toast.error("File not available for download"); return; }
    try {
      const token = localStorage.getItem("appsecdtoken");
      const res = await fetch(`${getApiBase()}/payloads/seclists/download/${f.id}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = f.filename || f.path.split("/").pop() || "wordlist.txt";
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Download started");
    } catch (e: any) {
      toast.error(e.message || "Download failed");
    }
  };

  const handleCopyContent = async (f: any) => {
    if (!f.id) return;
    try {
      const r = await api.seclistsContent(f.id);
      const content = r.content || r.lines?.join("\n") || "";
      await navigator.clipboard.writeText(content);
      toast.success(`Copied ${(r.lines?.length || content.split("\n").length).toLocaleString()} lines`);
    } catch (e: any) {
      toast.error(e.message || "Copy failed");
    }
  };

  const handlePreview = async (f: any) => {
    if (previewFile?.id === f.id) { setPreviewFile(null); return; }
    setPreviewFile(f);
    setPreviewLoading(true);
    try {
      const r = await api.seclistsPreview(f.path, 100);
      setPreviewContent(r.lines?.join("\n") || r.content || "Empty file");
    } catch {
      setPreviewContent("Failed to load preview");
    } finally {
      setPreviewLoading(false);
    }
  };

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-indigo-500 hover:text-indigo-400 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>

        <div className="flex items-center justify-between mb-2 flex-wrap gap-3">
          <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>SecLists — {catName}</h1>
          <span className="text-xs px-2.5 py-1 rounded-full" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
            {files.length} files
          </span>
        </div>
        <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
          Wordlist files for security testing. Use with ffuf, gobuster, sqlmap, etc.
        </p>

        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
          <input className="input-field pl-9 py-2 text-sm" placeholder="Filter files..."
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>

        {loading ? (
          <div className="space-y-2">{[1, 2, 3, 4, 5].map(i => <div key={i} className="card p-4 h-12 animate-shimmer" />)}</div>
        ) : filtered.length === 0 ? (
          <div className="card p-8 text-center" style={{ color: "var(--text-muted)" }}>No wordlist files {search ? "matching your search" : "in this category"}</div>
        ) : (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="card overflow-hidden">
            <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
              {filtered.map((f, i) => (
                <div key={f.path || i}>
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: Math.min(i * 0.01, 0.5) }}
                    className="flex items-center justify-between gap-3 py-2.5 px-4 hover:bg-[var(--bg-hover)] group transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0 flex-1">
                      <FileText className="w-4 h-4 shrink-0" style={{ color: "var(--text-muted)" }} />
                      <code className="text-sm font-mono truncate" style={{ color: "var(--text-code)" }}>{f.path}</code>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-xs tabular-nums" style={{ color: "var(--text-muted)" }}>{formatSize(f.size)}</span>
                      <button onClick={() => handlePreview(f)}
                        className="p-1.5 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                        style={{ color: previewFile?.id === f.id ? "var(--accent-indigo)" : "var(--text-muted)", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}
                        title="Preview">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => handleCopyContent(f)}
                        className="p-1.5 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                        style={{ color: "var(--text-muted)", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}
                        title="Copy content">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => handleDownload(f)}
                        className="p-1.5 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                        style={{ color: "var(--text-muted)", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}
                        title="Download">
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </motion.div>
                  {previewFile?.id === f.id && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
                      className="px-4 pb-3">
                      <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-subtle)" }}>
                        <div className="flex items-center justify-between px-3 py-1.5" style={{ background: "var(--bg-elevated)" }}>
                          <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>Preview (first 100 lines)</span>
                          <CopyBtn text={previewContent || ""} label="Copied preview" />
                        </div>
                        <pre className="p-3 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto leading-relaxed"
                          style={{ background: "var(--bg-tertiary)", color: "var(--text-code)" }}>
                          {previewLoading ? "Loading..." : previewContent}
                        </pre>
                      </div>
                    </motion.div>
                  )}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
