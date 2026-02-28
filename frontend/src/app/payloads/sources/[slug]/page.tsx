"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api, getApiBase } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft, FileText, Copy, Download } from "lucide-react";
import toast from "react-hot-toast";

export default function PayloadSourcePage() {
  const params = useParams();
  const slug = params.slug as string;
  const { hydrate } = useAuthStore();
  const [files, setFiles] = useState<{ path: string; size: number; id?: string; filename?: string }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (!slug) return;
    api.sourceFiles(decodeURIComponent(slug))
      .then(r => setFiles(r.files || []))
      .catch(() => setFiles([]))
      .finally(() => setLoading(false));
  }, [slug]);

  const sourceName = decodeURIComponent(slug).replace(/-/g, " ").replace(/_/g, " ");
  const formatSize = (bytes: number) =>
    bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

  const handleCopy = async (f: { id?: string }) => {
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

  const handleDownload = async (f: { id?: string; filename?: string; path: string }) => {
    if (!f.id) return;
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
      a.download = f.filename || f.path.split("/").pop() || "payload.txt";
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Download started");
    } catch (e: any) {
      toast.error(e.message || "Download failed");
    }
  };

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>
        <h1 className="text-2xl font-bold text-white mb-2">{sourceName}</h1>
        <p className="text-[#9CA3AF] text-sm mb-6">
          Payload files for security testing. Copy or download for use with ffuf, sqlmap, burp, etc.
        </p>
        {loading ? (
          <div className="text-center text-[#9CA3AF] py-16">Loading...</div>
        ) : files.length === 0 ? (
          <div className="card p-8 text-center text-[#9CA3AF]">
            No files. Run sync script: <code className="text-blue-400">python scripts/sync_all_payloads.py</code>
          </div>
        ) : (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="card p-4">
            <div className="space-y-1 max-h-[70vh] overflow-y-auto">
              {files.map((f, i) => (
                <motion.div
                  key={f.path}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.01 }}
                  className="flex items-center justify-between gap-3 py-2 px-3 rounded hover:bg-[#1F2937] group"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FileText className="w-4 h-4 text-[#6B7280] shrink-0" />
                    <code className="text-sm text-[#A5F3FC] truncate font-mono">{f.path}</code>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-xs text-[#6B7280]">{formatSize(f.size)}</span>
                    <button onClick={() => handleCopy(f)}
                      className="opacity-0 group-hover:opacity-100 p-1.5 rounded bg-[#374151] hover:bg-blue-600 hover:text-white text-[#9CA3AF] transition-opacity"
                      title="Copy content">
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => handleDownload(f)}
                      className="opacity-0 group-hover:opacity-100 p-1.5 rounded bg-[#374151] hover:bg-green-600 hover:text-white text-[#9CA3AF] transition-opacity"
                      title="Download">
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
