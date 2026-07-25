import { useState } from "react";
import { Info, ChevronRight, BookOpen } from "lucide-react";
import { GuideSection } from "./GuideSection";
import {
  SectionSeeds,
  SectionFPE,
  SectionChain,
  SectionKAnon,
  SectionLDiv,
  SectionTClose,
  SectionReID,
} from "./InfoSections";

const SECTIONS = [
  { id: "guide",   label: "Interactive Guide" },
  { id: "seeds",   label: "Seed → Key Generation" },
  { id: "fpe",     label: "Format-Preserving Encryption" },
  { id: "chain",   label: "4-Round Chain" },
  { id: "kanon",   label: "k-Anonymity & Link Score" },
  { id: "ldiv",    label: "l-Diversity" },
  { id: "tclose",  label: "t-Closeness" },
  { id: "reid",    label: "Re-ID Risk & Metrics" },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

const SECTION_CONTENT: Record<SectionId, React.ReactNode> = {
  guide:   <GuideSection />,
  seeds:   <SectionSeeds />,
  fpe:     <SectionFPE />,
  chain:   <SectionChain />,
  kanon:   <SectionKAnon />,
  ldiv:    <SectionLDiv />,
  tclose:  <SectionTClose />,
  reid:    <SectionReID />,
};

export function InfoButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 text-sm font-medium hover:bg-slate-50 hover:border-slate-300 hover:text-slate-800 transition-all shadow-sm"
    >
      <Info className="w-4 h-4" />
      Info
    </button>
  );
}

export function InfoModal() {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState<SectionId>("guide");

  return (
    <>
      <InfoButton onClick={() => setOpen(true)} />

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          />
          <div className="relative z-10 bg-white shadow-2xl w-full h-full flex flex-col overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-gradient-to-r from-indigo-600 to-violet-600 shrink-0">
              <div className="flex items-center gap-3">
                {active !== "guide" && (
                  <button
                    onClick={() => setActive("guide")}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/20 hover:bg-white/30 text-white text-sm font-medium transition-colors"
                  >
                    <ChevronRight className="w-4 h-4 rotate-180" />
                    Guide
                  </button>
                )}
                <div>
                  <h2 className="text-xl font-bold text-white tracking-tight">
                    {active === "guide" ? "How Anonymization Works — Interactive Guide" : "Mathematical Reference"}
                  </h2>
                  <p className="text-indigo-200 text-xs mt-0.5">
                    {active === "guide"
                      ? "Step-by-step walkthrough with live calculations"
                      : "Key generation, format-preserving encryption, and privacy metrics"}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="w-8 h-8 rounded-full flex items-center justify-center bg-white/20 hover:bg-white/30 text-white transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Body */}
            <div className="flex flex-1 min-h-0">
              {/* Sidebar — hidden when Guide is active */}
              {active !== "guide" && (
                <nav className="w-56 shrink-0 border-r border-slate-200 bg-slate-50 py-4 flex flex-col gap-0.5 px-2 overflow-y-auto">
                  {SECTIONS.map(s => (
                    <button
                      key={s.id}
                      onClick={() => setActive(s.id)}
                      className={`w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                        active === s.id
                          ? "bg-indigo-600 text-white shadow"
                          : s.id === "guide"
                          ? "text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200"
                          : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                      }`}
                    >
                      {s.id === "guide" && <BookOpen className="w-3.5 h-3.5 shrink-0" />}
                      <span>{s.label}</span>
                    </button>
                  ))}
                  <div className="mt-2 mx-1 border-t border-slate-200 pt-2">
                    <p className="text-xs text-slate-400 px-2">Mathematical Reference</p>
                  </div>
                </nav>
              )}

              {/* Content */}
              {active === "guide" ? (
                <div className="flex-1 flex flex-col min-h-0">
                  <GuideSection />
                </div>
              ) : (
                <div className="flex-1 overflow-y-auto px-8 py-6">
                  <h2 className="text-lg font-bold text-slate-900 mb-1 border-b border-slate-100 pb-3">
                    {SECTIONS.find(s => s.id === active)?.label}
                  </h2>
                  {SECTION_CONTENT[active]}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
