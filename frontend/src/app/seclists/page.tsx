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
    <div className="min-h-screen p-8" style={{ background: "var(--bg-primary)" }}>
      <header className="mb-8">
        <Link href="/" className="text-indigo-400 hover:underline text-sm mb-4 inline-block">
          Back
        </Link>
        <h1 className="text-2xl font-bold" style={{ color: "var(--accent-cyan)" }}>SecLists</h1>
        <p className="mt-1" style={{ color: "var(--text-secondary)" }}>
          Security wordlists: usernames, passwords, URLs, fuzzing payloads
        </p>
      </header>

      {loading ? (
        <p style={{ color: "var(--accent-yellow)" }}>Loading categories...</p>
      ) : (
        <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {categories.map((c) => (
            <Link
              key={c.id}
              href={`/seclists/${encodeURIComponent(c.id)}`}
              className="p-4 rounded card transition-colors"
            >
              <span style={{ color: "var(--text-primary)" }}>{c.name}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
