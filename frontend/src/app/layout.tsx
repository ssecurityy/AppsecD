import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "react-hot-toast";
import { ThemeProvider } from "@/components/ThemeProvider";

export const metadata: Metadata = {
  title: "AppSecD",
  description: "Enterprise Application Security Testing & Vulnerability Management Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className="antialiased min-h-screen font-sans" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
        <ThemeProvider>
          {children}
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 3000,
              style: {
                background: "var(--toast-bg)",
                color: "var(--text-primary)",
                border: "1px solid var(--toast-border)",
                borderRadius: "12px",
                fontSize: "13px",
                boxShadow: "0 8px 32px rgba(0,0,0,0.15)",
              },
              success: {
                iconTheme: { primary: "#10b981", secondary: "var(--toast-bg)" },
              },
              error: {
                iconTheme: { primary: "#ef4444", secondary: "var(--toast-bg)" },
              },
            }}
          />
        </ThemeProvider>
      </body>
    </html>
  );
}
