"use client";
import { useEffect } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft } from "lucide-react";

export default function SecListsCategoryPage() {
  const params = useParams();
  const { hydrate } = useAuthStore();
  const category = params.category as string;
  const catName = decodeURIComponent(category).replace(/-/g, " ");

  useEffect(() => { hydrate(); }, [hydrate]);

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-indigo-400 hover:text-blue-300 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>
        <h1 className="text-2xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>SecLists — {catName}</h1>
        <div className="card p-8 text-center" style={{ color: "var(--text-secondary)" }}>
          SecLists files are available on the server at:<br />
          <code className="text-indigo-400">/opt/navigator/data/SecLists/{category}/</code>
        </div>
      </div>
    </div>
  );
}
