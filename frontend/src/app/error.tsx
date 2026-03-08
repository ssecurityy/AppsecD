"use client";

import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Page error caught by error boundary:", error);
  }, [error]);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg-primary)" }}>
      <div className="text-center max-w-md mx-auto px-6">
        <div className="w-16 h-16 mx-auto mb-6 rounded-full flex items-center justify-center" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)" }}>
          <svg className="w-8 h-8 text-red-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
        </div>
        <h2 className="text-xl font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
          Something went wrong
        </h2>
        <p className="text-sm mb-6" style={{ color: "var(--text-secondary)" }}>
          An unexpected error occurred. This is usually temporary.
          {error?.digest && (
            <span className="block mt-1 text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
              Error ID: {error.digest}
            </span>
          )}
        </p>
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={() => reset()}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-all"
            style={{ background: "rgba(99,102,241,0.15)", color: "#818cf8", border: "1px solid rgba(99,102,241,0.3)" }}
          >
            Try Again
          </button>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-all"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
          >
            Reload Page
          </button>
          <button
            onClick={() => window.location.href = "/dashboard"}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-all"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
