"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft, FileText, Copy } from "lucide-react";
import toast from "react-hot-toast";

export default function SecListsCategoryPage() {
  const params = useParams();
  const category = params.category as string;
  const { hydrate } = useAuthStore();
  const [files, setFiles] = useState<{ path: string; size: number }[]>([]);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>
        <h1 className="text-2xl font-bold text-white mb-2">SecLists — {catName}</h1>
        <p className="text-[#9CA3AF] text-sm mb-6">
          Wordlist files for security testing. Use with ffuf, gobuster, sqlmap, etc.
        </p>
        {loading ? (
          <div className="text-center text-[#9CA3AF] py-16">Loading wordlists...</div>
        ) : files.length === 0 ? (
          <div className="card p-8 text-center text-[#9CA3AF]">No wordlist files in this category</div>
        ) : (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="card p-4">
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
                    <button
                      onClick={() => {
                        const fullPath = `${category}/${f.path}`;
                        navigator.clipboard.writeText(`/opt/navigator/data/SecLists/${fullPath}`);
                        toast.success("Path copied! Use in terminal.");
                      }}
                      className="opacity-0 group-hover:opacity-100 p-1.5 rounded bg-[#374151] hover:bg-[#4B5563] text-[#9CA3AF] transition-opacity"
                      title="Copy full path"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
            <p className="text-xs text-[#6B7280] mt-4 pt-4 border-t border-[#1F2937]">
              Path on server: <code className="text-[#9CA3AF]">/opt/navigator/data/SecLists/{decodeURIComponent(category)}/</code>
            </p>
          </motion.div>
        )}
      </div>
    </div>
  );
}
