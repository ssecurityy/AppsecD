"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

export default function SecListsPage() {
  const [categories, setCategories] = useState<{ id: string; name: string }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.seclistsCategories()
      .then((r: { categories?: { id: string; name: string }[] }) => setCategories(r.categories ?? []))
      .catch(() => setCategories([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen p-8">
      <header className="mb-8">
        <Link href="/" className="text-[#3B82F6] hover:underline text-sm mb-4 inline-block">
          ← Back
        </Link>
        <h1 className="text-2xl font-bold text-[#06B6D4]">SecLists</h1>
        <p className="text-[#9CA3AF] mt-1">
          Security wordlists: usernames, passwords, URLs, fuzzing payloads
        </p>
      </header>

      {loading ? (
        <p className="text-[#F59E0B]">Loading categories...</p>
      ) : (
        <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {categories.map((c) => (
            <Link
              key={c.id}
              href={`/seclists/${encodeURIComponent(c.id)}`}
              className="p-4 rounded bg-[#111827] border border-[#1F2937] hover:border-[#3B82F6] transition-colors"
            >
              <span className="text-[#F9FAFB]">{c.name}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
