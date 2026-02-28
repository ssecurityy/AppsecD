"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { ChevronLeft, Copy, Check, Terminal, Search, ChevronRight } from "lucide-react";
import toast from "react-hot-toast";

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success(label ? `Copied: ${label}` : "Copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy}
      className="copy-btn flex items-center gap-1 text-xs px-2 py-1 shrink-0"
      title="Copy to clipboard">
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

function CodeBlock({ content }: { content: string }) {
  return (
    <div className="relative group rounded-lg overflow-hidden border" style={{ borderColor: "var(--border-subtle)" }}>
      <div className="flex items-center justify-between px-3 py-1.5" style={{ background: "var(--bg-elevated)" }}>
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
          <span className="text-[10px] font-medium" style={{ color: "var(--text-muted)" }}>payload</span>
        </div>
        <CopyButton text={content} />
      </div>
      <pre className="p-3 text-xs font-mono overflow-x-auto leading-relaxed" style={{ background: "var(--bg-tertiary)", color: "var(--text-code)" }}>
        {content}
      </pre>
    </div>
  );
}

export default function PayloadPatCategoryPage() {
  const params = useParams();
  const category = params.category as string;
  const { hydrate } = useAuthStore();
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => {
    if (!category) return;
    const decoded = decodeURIComponent(category);
    api.payloadContent(decoded)
      .then(r => setContent(r.content || null))
      .catch(() => setContent(null))
      .finally(() => setLoading(false));
  }, [category]);

  const catName = decodeURIComponent(category).replace(/-/g, " ").replace(/_/g, " ");

  const parseContent = useCallback((raw: string) => {
    const lines = raw.split("\n");
    const sections: { title: string; blocks: { type: "text" | "code" | "command"; content: string }[] }[] = [];
    let currentSection: typeof sections[0] = { title: "Overview", blocks: [] };
    let inCodeBlock = false;
    let codeBuffer: string[] = [];

    for (const line of lines) {
      if (line.startsWith("```")) {
        if (inCodeBlock) {
          currentSection.blocks.push({ type: "code", content: codeBuffer.join("\n") });
          codeBuffer = [];
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
        }
        continue;
      }
      if (inCodeBlock) { codeBuffer.push(line); continue; }
      if (line.startsWith("# ")) {
        if (currentSection.blocks.length > 0 || currentSection.title !== "Overview") sections.push(currentSection);
        currentSection = { title: line.slice(2).trim(), blocks: [] };
      } else if (line.startsWith("## ") || line.startsWith("### ")) {
        if (currentSection.blocks.length > 0) sections.push(currentSection);
        currentSection = { title: line.replace(/^#+\s/, ""), blocks: [] };
      } else if (/^\s*(\$\s+|curl |sqlmap |ffuf |nmap |python |gobuster |wfuzz |hydra |nikto )/.test(line)) {
        currentSection.blocks.push({ type: "command", content: line.trim().replace(/^\$\s+/, "") });
      } else if (line.trim()) {
        const lastBlock = currentSection.blocks[currentSection.blocks.length - 1];
        if (lastBlock?.type === "text") { lastBlock.content += "\n" + line; }
        else { currentSection.blocks.push({ type: "text", content: line }); }
      }
    }
    if (codeBuffer.length > 0) currentSection.blocks.push({ type: "code", content: codeBuffer.join("\n") });
    if (currentSection.blocks.length > 0 || sections.length === 0) sections.push(currentSection);
    return sections;
  }, []);

  const filteredContent = content && search
    ? content.split("\n").filter(l => l.toLowerCase().includes(search.toLowerCase())).join("\n")
    : content;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <Link href="/payloads" className="flex items-center gap-1 text-indigo-500 hover:text-indigo-400 text-sm mb-4">
          <ChevronLeft className="w-4 h-4" /> Back to Library
        </Link>

        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>{catName}</h1>
          {content && (
            <div className="flex items-center gap-2">
              <CopyButton text={content} label="all content" />
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                <input className="input-field pl-8 py-1.5 text-xs w-48" placeholder="Search payloads..."
                  value={search} onChange={e => setSearch(e.target.value)} />
              </div>
            </div>
          )}
        </div>

        {loading ? (
          <div className="space-y-3">{[1, 2, 3].map(i => <div key={i} className="card p-6 h-24 animate-shimmer" />)}</div>
        ) : content ? (
          <div className="space-y-4">
            {search ? (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="card p-4">
                <div className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                  {filteredContent?.split("\n").filter(l => l.trim()).length || 0} matching lines
                </div>
                <div className="space-y-1 max-h-[70vh] overflow-y-auto">
                  {filteredContent?.split("\n").filter(l => l.trim()).map((line, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 py-1.5 px-2 rounded hover:bg-[var(--bg-hover)] group">
                      <code className="text-xs font-mono break-all flex-1" style={{ color: "var(--text-code)" }}>{line}</code>
                      <CopyButton text={line} />
                    </div>
                  ))}
                </div>
              </motion.div>
            ) : (
              parseContent(content).map((section, si) => (
                <motion.div key={si} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: si * 0.05 }} className="card p-5 overflow-hidden">
                  <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                    <ChevronRight className="w-3.5 h-3.5 text-indigo-500" />
                    {section.title}
                  </h2>
                  <div className="space-y-3">
                    {section.blocks.map((block, bi) => {
                      if (block.type === "code") return <CodeBlock key={bi} content={block.content} />;
                      if (block.type === "command") {
                        return (
                          <div key={bi} className="flex items-center gap-2 rounded-lg px-3 py-2 font-mono text-xs group"
                            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                            <span className="text-emerald-500 shrink-0">$</span>
                            <code className="flex-1 break-all" style={{ color: "var(--text-code)" }}>{block.content}</code>
                            <CopyButton text={block.content} label="command" />
                          </div>
                        );
                      }
                      return (
                        <p key={bi} className="text-sm leading-relaxed whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
                          {block.content}
                        </p>
                      );
                    })}
                  </div>
                </motion.div>
              ))
            )}
          </div>
        ) : (
          <div className="card p-8 text-center" style={{ color: "var(--text-muted)" }}>Content not found</div>
        )}
      </div>
    </div>
  );
}
