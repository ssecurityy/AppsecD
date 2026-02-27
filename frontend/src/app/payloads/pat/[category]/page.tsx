"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft } from "lucide-react";

export default function PayloadPatCategoryPage() {
  const params = useParams();
  const category = params.category as string;
  const { hydrate } = useAuthStore();
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (!category) return;
    const decoded = decodeURIComponent(category);
    api.payloadContent(decoded)
      .then(r => setContent(r.content || null))
      .catch(() => setContent(null))
      .finally(() => setLoading(false));
  }, [category]);

  const catName = decodeURIComponent(category).replace(/-/g, " ").replace(/_/g, " ");

  return (
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>
        <h1 className="text-2xl font-bold text-white mb-4">{catName}</h1>
        {loading ? (
          <div className="text-center text-[#9CA3AF] py-16">Loading payloads...</div>
        ) : content ? (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="card p-6 overflow-x-auto">
            <pre className="text-xs text-[#A5F3FC] font-mono whitespace-pre-wrap leading-relaxed">
              {content}
            </pre>
          </motion.div>
        ) : (
          <div className="card p-8 text-center text-[#9CA3AF]">Content not found</div>
        )}
      </div>
    </div>
  );
}
