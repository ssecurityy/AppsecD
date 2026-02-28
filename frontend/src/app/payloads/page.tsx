"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { useRouter } from "next/navigation";
import { BookOpen, Search, Database, FileText, FolderOpen, Layers } from "lucide-react";

export default function WordlistsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [categories, setCategories] = useState<any[]>([]);
  const [seclists, setSeclists] = useState<any[]>([]);
  const [sources, setSources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState<"pat" | "seclists" | "sources">("pat");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  useEffect(() => {
    Promise.all([
      api.payloadCategories(),
      api.seclistsCategories(),
      api.payloadSources(),
    ])
      .then(([p, s, src]) => {
        setCategories(p.categories || []);
        setSeclists(s.categories || []);
        setSources(src.sources || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const filtered = tab === "pat"
    ? categories.filter(c => c.name.toLowerCase().includes(search.toLowerCase()))
    : tab === "seclists"
      ? seclists.filter(c => c.name.toLowerCase().includes(search.toLowerCase()))
      : sources.filter((s: any) => s.name.toLowerCase().includes(search.toLowerCase()));

  const tabs = [
    { key: "pat" as const, label: "Test Payloads", icon: FileText, count: categories.length },
    { key: "seclists" as const, label: "SecLists", icon: Database, count: seclists.length },
    { key: "sources" as const, label: "Sources", icon: Layers, count: sources.length },
  ];

  return (
    <div className="min-h-screen bg-[#09090b]">
      <Navbar />
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/10 flex items-center justify-center">
              <BookOpen className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Wordlists & Test Payloads</h1>
              <p className="text-sm text-[#64748b]">Comprehensive collection of security testing resources from PostgreSQL</p>
            </div>
          </div>
        </motion.div>

        {/* Tabs + Search */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex bg-[#111827] rounded-lg p-1 border border-[#1e2330]">
            {tabs.map(t => (
              <button key={t.key} onClick={() => { setTab(t.key); setSearch(""); }}
                className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${
                  tab === t.key ? "bg-indigo-500 text-white" : "text-[#94a3b8] hover:text-white"
                }`}>
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  tab === t.key ? "bg-white/20" : "bg-[#1e2330]"
                }`}>{t.count}</span>
              </button>
            ))}
          </div>
          <div className="flex-1 relative min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#64748b]" />
            <input className="input-field pl-9 py-2 text-sm" placeholder="Search categories..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>

        {/* Content */}
        {loading ? (
          <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {[1, 2, 3, 4, 5, 6, 7, 8].map(i => (
              <div key={i} className="card p-4 h-16 animate-shimmer" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-16 text-center border-dashed">
            <FolderOpen className="w-10 h-10 text-[#334155] mx-auto mb-3" />
            <p className="text-[#64748b] text-sm">No categories found</p>
            {search && <p className="text-[#475569] text-xs mt-1">Try a different search term</p>}
          </div>
        ) : (
          <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {filtered.map((c, i) => (
              <motion.div key={c.id || c.slug} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.015 }}>
                <Link href={
                  tab === "pat" ? `/payloads/pat/${encodeURIComponent(c.id)}`
                  : tab === "seclists" ? `/payloads/seclists/${encodeURIComponent(c.id)}`
                  : `/payloads/sources/${encodeURIComponent(c.slug)}`
                }
                  className="card p-4 block hover:border-indigo-500/20 transition-all group">
                  <div className="flex items-center gap-2">
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                      tab === "pat" ? "bg-indigo-500/10 text-indigo-400" :
                      tab === "seclists" ? "bg-blue-500/10 text-blue-400" :
                      "bg-emerald-500/10 text-emerald-400"
                    }`}>
                      {tab === "pat" ? <FileText className="w-3.5 h-3.5" /> :
                       tab === "seclists" ? <Database className="w-3.5 h-3.5" /> :
                       <Layers className="w-3.5 h-3.5" />}
                    </div>
                    <span className="text-sm text-white group-hover:text-indigo-400 transition-colors line-clamp-2 flex-1">
                      {c.name}
                    </span>
                  </div>
                  {c.file_count && (
                    <div className="text-[10px] text-[#475569] mt-2 ml-9">{c.file_count} files</div>
                  )}
                </Link>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
