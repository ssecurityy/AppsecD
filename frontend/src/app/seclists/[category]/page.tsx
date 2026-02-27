"use client";
import { useEffect, useState } from "react";
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
    <div className="min-h-screen">
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>
        <h1 className="text-2xl font-bold text-white mb-4">SecLists — {catName}</h1>
        <div className="card p-8 text-center text-[#9CA3AF]">
          SecLists files are available on the server at:<br />
          <code className="text-blue-400">/opt/navigator/data/SecLists/{category}/</code>
        </div>
      </div>
    </div>
  );
}
