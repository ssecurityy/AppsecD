"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import {
  ClipboardList, Zap, Code2, ShieldCheck, FileText, ArrowLeft,
} from "lucide-react";

interface ProjectSubNavProps {
  projectId: string;
  projectName?: string;
  projectUrl?: string;
  sastEnabled?: boolean;
}

const TABS = [
  { key: "overview", href: "", label: "Overview", icon: ClipboardList },
  { key: "dast", href: "/dast", label: "DAST Scan", icon: Zap },
  { key: "sast", href: "/sast", label: "SAST Scan", icon: Code2 },
  { key: "vulnerabilities", href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldCheck },
  { key: "report", href: "/report", label: "Report", icon: FileText },
];

export default function ProjectSubNav({ projectId, projectName, projectUrl, sastEnabled = true }: ProjectSubNavProps) {
  const pathname = usePathname();
  const basePath = `/projects/${projectId}`;

  const visibleTabs = TABS.filter((t) => {
    if (t.key === "sast" && !sastEnabled) return false;
    return true;
  });

  const activeKey = (() => {
    const sub = pathname.replace(basePath, "").replace(/^\//, "").split("/")[0];
    if (!sub) return "overview";
    return visibleTabs.find((t) => t.key === sub)?.key || "overview";
  })();

  return (
    <div className="mb-6">
      {/* Back + Project Info */}
      <div className="flex items-center gap-3 mb-4">
        <Link href="/projects" className="p-2 rounded-lg transition-colors" style={{ color: "var(--text-secondary)" }}
          title="Back to Projects">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="min-w-0">
          {projectName && (
            <h1 className="text-lg font-bold truncate" style={{ color: "var(--text-primary)" }}>
              {projectName}
            </h1>
          )}
          {projectUrl && (
            <a href={projectUrl} target="_blank" rel="noopener noreferrer"
              className="text-xs truncate block hover:underline" style={{ color: "var(--accent)" }}>
              {projectUrl}
            </a>
          )}
        </div>
      </div>

      {/* Tab Bar */}
      <div className="flex items-center gap-1 border-b overflow-x-auto scrollbar-none pb-0" style={{ borderColor: "var(--border-subtle)" }}>
        {visibleTabs.map(({ key, href, label, icon: Icon }) => {
          const active = activeKey === key;
          const fullHref = key === "overview" ? basePath : `${basePath}${href}`;
          return (
            <Link
              key={key}
              href={fullHref}
              className={`relative flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
                active ? "" : "hover:bg-[var(--bg-hover)]"
              }`}
              style={{
                color: active ? "var(--text-primary)" : "var(--text-muted)",
                borderRadius: "0.5rem 0.5rem 0 0",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
              {active && (
                <motion.div
                  layoutId="project-tab-indicator"
                  className="absolute bottom-0 left-2 right-2 h-[2px] rounded-full"
                  style={{ background: key === "dast" ? "#10b981" : key === "sast" ? "#8b5cf6" : "#6366f1" }}
                  transition={{ type: "spring", bounce: 0.15, duration: 0.4 }}
                />
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
