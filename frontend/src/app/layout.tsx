import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "react-hot-toast";

export const metadata: Metadata = {
  title: "AppSecD",
  description: "Enterprise Application Security Testing & Vulnerability Management Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased min-h-screen bg-[#09090b] text-[#F1F5F9] font-sans">
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 3000,
            style: {
              background: "#161922",
              color: "#F1F5F9",
              border: "1px solid #1e2330",
              borderRadius: "12px",
              fontSize: "13px",
              boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
            },
            success: {
              iconTheme: { primary: "#10b981", secondary: "#161922" },
            },
            error: {
              iconTheme: { primary: "#ef4444", secondary: "#161922" },
            },
          }}
        />
      </body>
    </html>
  );
}
