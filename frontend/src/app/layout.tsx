import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "react-hot-toast";

export const metadata: Metadata = {
  title: "VAPT Navigator",
  description: "Intelligent Web Application Security Testing Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased min-h-screen bg-[#0A0F1E] text-[#F9FAFB] font-sans">
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: "#1F2937",
              color: "#F9FAFB",
              border: "1px solid #374151",
            },
          }}
        />
      </body>
    </html>
  );
}
