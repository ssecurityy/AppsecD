"use client";

/**
 * Global error boundary — catches errors in the root layout itself.
 * Must include <html> and <body> since it replaces the entire root layout.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body style={{ background: "#0a0a0f", color: "#e2e8f0", fontFamily: "system-ui, sans-serif", margin: 0 }}>
        <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ textAlign: "center", maxWidth: "420px", padding: "24px" }}>
            <div style={{
              width: "64px", height: "64px", margin: "0 auto 24px",
              borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
              background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)",
            }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
              </svg>
            </div>
            <h2 style={{ fontSize: "20px", fontWeight: 600, marginBottom: "8px" }}>
              Application Error
            </h2>
            <p style={{ fontSize: "14px", color: "#94a3b8", marginBottom: "24px" }}>
              A critical error occurred. Please try reloading the page.
              {error?.digest && (
                <span style={{ display: "block", marginTop: "4px", fontSize: "10px", fontFamily: "monospace", color: "#64748b" }}>
                  ID: {error.digest}
                </span>
              )}
            </p>
            <div style={{ display: "flex", gap: "12px", justifyContent: "center" }}>
              <button
                onClick={() => reset()}
                style={{
                  padding: "8px 16px", borderRadius: "8px", fontSize: "14px", fontWeight: 500,
                  background: "rgba(99,102,241,0.15)", color: "#818cf8",
                  border: "1px solid rgba(99,102,241,0.3)", cursor: "pointer",
                }}
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                style={{
                  padding: "8px 16px", borderRadius: "8px", fontSize: "14px", fontWeight: 500,
                  background: "rgba(255,255,255,0.05)", color: "#94a3b8",
                  border: "1px solid rgba(255,255,255,0.1)", cursor: "pointer",
                }}
              >
                Reload Page
              </button>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
