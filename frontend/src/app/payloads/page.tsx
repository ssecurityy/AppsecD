"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { useRouter } from "next/navigation";
import { BookOpen, Search } from "lucide-react";

export default function PayloadsPage() {
  const { hydrate, user } = useAuthStore();
  const router = useRouter();
  const [categories, setCategories] = useState<any[]>([]);
  const [seclists, setSeclists] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState<"pat" | "seclists">("pat");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (!user && !loading) router.replace("/login"); }, [user, router, loading]);

  useEffect(() => {
    Promise.all([api.payloadCategories(), api.seclistsCategories()])
      .then(([p, s]) => { setCategories(p.categories || []); setSeclists(s.categories || []); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const filtered = tab === "pat"
    ? categories.filter(c => c.name.toLowerCase().includes(search.toLowerCase()))
    : seclists.filter(c => c.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <div className="flex items-center gap-3 mb-6">
          <BookOpen className="w-6 h-6 text-blue-400" />
          <h1 className="text-2xl font-bold text-white">Payload & Wordlist Library</h1>
        </div>

        <div className="flex items-center gap-3 mb-4">
          <div className="flex bg-[#111827] rounded-lg p-1 border border-[#1F2937]">
            {(["pat", "seclists"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${
                  tab === t ? "bg-blue-600 text-white" : "text-[#9CA3AF] hover:text-white"
                }`}>
                {t === "pat" ? "PayloadsAllTheThings" : "SecLists"}
              </button>
            ))}
          </div>
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6B7280]" />
            <input className="input-field pl-9 py-1.5 text-sm" placeholder="Search categories..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>

        {loading ? (
          <div className="text-center text-[#9CA3AF] py-16">Loading...</div>
        ) : (
          <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {filtered.map((c, i) => (
              <motion.div key={c.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.02 }}>
                <Link href={tab === "pat" ? `/payloads/pat/${encodeURIComponent(c.id)}` : `/payloads/seclists/${encodeURIComponent(c.id)}`}
                  className="card p-3 block hover:border-blue-700/50 transition-all group">
                  <span className="text-sm text-white group-hover:text-blue-400 transition-colors line-clamp-2">
                    {c.name}
                  </span>
                </Link>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
