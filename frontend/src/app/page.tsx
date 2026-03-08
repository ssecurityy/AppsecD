"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";

export default function RootPage() {
  const router = useRouter();
  const { hydrate, user } = useAuthStore();
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    hydrate();
    setHydrated(true);
  }, [hydrate]);

  useEffect(() => {
    if (!hydrated) return;
    router.replace(user ? "/dashboard" : "/login");
  }, [user, router, hydrated]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-[#94a3b8]">Loading AppSecD...</div>
    </div>
  );
}
