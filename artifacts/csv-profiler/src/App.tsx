import { Switch, Route, Router as WouterRouter, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Shield, Info } from "lucide-react";
import NotFound from "@/pages/not-found";
import FWFConverter from "@/pages/FWFConverter";
import InfoPage from "@/pages/Info";
import RiskAssessmentSingle, { pageCache } from "@/pages/RiskAssessmentSingle";
import RiskAssessmentComparison from "@/pages/RiskAssessmentComparison";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000,
      refetchOnWindowFocus: false,
    },
  },
});

function AppLayout() {
  const [location, navigate] = useLocation();
  const onOriginal   = location.startsWith("/risk-assessment/original");
  const onAnonymized = location.startsWith("/risk-assessment/anonymized");
  const onComparison = location.startsWith("/risk-assessment/comparison");
  const onRisk       = onOriginal || onAnonymized || onComparison;

  const bothReady = !!pageCache.original.result && !!pageCache.anonymized.result;

  return (
    <div className="min-h-screen bg-white">
      <header className="border-b border-gray-200 bg-white px-8 py-4">
        <div className="max-w-[1400px] mx-auto flex items-center gap-3 flex-wrap">
          <button onClick={() => navigate("/")} className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <img src={`${import.meta.env.BASE_URL}airavata-logo.png`} alt="Airavata logo" className="w-10 h-10 object-contain" />
            <div className="text-left">
              <span className="text-xl font-semibold text-black tracking-tight">AIRAVATA DEA</span>
              <p className="text-sm text-gray-500 leading-none mt-0.5">Convert, Anonymize &amp; Decrypt</p>
            </div>
          </button>

          <div className="flex-1" />

          <button
            onClick={() => navigate("/info")}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 text-sm font-medium hover:bg-slate-50 hover:border-slate-300 hover:text-slate-800 transition-all shadow-sm"
          >
            <Info className="w-4 h-4" />
            Info
          </button>

          {/* Risk Assessment nav — split buttons */}
          <div className="flex items-center gap-1">
            <div className="flex items-center gap-0.5 border border-indigo-200 rounded-xl overflow-hidden bg-indigo-50">
              <span className="flex items-center gap-1.5 pl-3 pr-2 py-2 text-xs font-bold text-indigo-500 select-none">
                <Shield className="w-3.5 h-3.5" />Risk Assessment
              </span>
              <div className="w-px h-5 bg-indigo-200" />
              <button
                onClick={() => navigate("/risk-assessment/original")}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-semibold transition-colors ${
                  onOriginal
                    ? "bg-blue-600 text-white"
                    : "text-blue-700 hover:bg-blue-100"
                }`}>
                📄 Original File
              </button>
              <div className="w-px h-5 bg-indigo-200" />
              <button
                onClick={() => navigate("/risk-assessment/anonymized")}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-semibold transition-colors ${
                  onAnonymized
                    ? "bg-purple-600 text-white"
                    : "text-purple-700 hover:bg-purple-100"
                }`}>
                🔒 Anonymized File
              </button>
              <div className="w-px h-5 bg-indigo-200" />
              <button
                onClick={() => navigate("/risk-assessment/comparison")}
                title={bothReady ? "Compare both datasets" : "Run both analyses first to unlock comparison"}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-semibold transition-colors ${
                  onComparison
                    ? "bg-teal-600 text-white"
                    : bothReady
                      ? "text-teal-700 hover:bg-teal-100"
                      : "text-teal-400 hover:bg-teal-50"
                }`}>
                ⚖️ Comparison
                {bothReady && !onComparison && (
                  <span className="w-1.5 h-1.5 rounded-full bg-teal-500 ml-0.5" />
                )}
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-[1400px] mx-auto px-8 py-8">
        <Switch>
          <Route path="/" component={FWFConverter} />
          <Route path="/fwf" component={FWFConverter} />
          <Route path="/info" component={InfoPage} />
          <Route path="/risk-assessment/original">
            {() => <RiskAssessmentSingle key="original" mode="original" />}
          </Route>
          <Route path="/risk-assessment/anonymized">
            {() => <RiskAssessmentSingle key="anonymized" mode="anonymized" />}
          </Route>
          <Route path="/risk-assessment/comparison">
            {() => <RiskAssessmentComparison />}
          </Route>
          <Route path="/risk-assessment">
            {() => <RiskAssessmentLanding navigate={navigate} />}
          </Route>
          <Route component={NotFound} />
        </Switch>
      </main>
    </div>
  );
}

function RiskAssessmentLanding({ navigate }: { navigate: (to: string) => void }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] gap-8">
      <div className="text-center space-y-2">
        <div className="w-14 h-14 rounded-2xl bg-indigo-600 flex items-center justify-center mx-auto">
          <Shield className="w-7 h-7 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-black mt-4">Risk Assessment</h1>
        <p className="text-sm text-gray-500">Choose a dataset type to evaluate re-identification risk</p>
      </div>
      <div className="flex gap-6 flex-wrap justify-center">
        <button
          onClick={() => navigate("/risk-assessment/original")}
          className="flex flex-col items-center gap-3 w-56 p-8 border-2 border-blue-200 rounded-2xl bg-blue-50 hover:bg-blue-100 hover:border-blue-400 transition-all text-left group">
          <span className="text-4xl">📄</span>
          <div>
            <p className="font-bold text-blue-800 text-base">Original File</p>
            <p className="text-xs text-blue-600 mt-1">Analyse the unmodified source dataset for re-identification risk</p>
          </div>
        </button>
        <button
          onClick={() => navigate("/risk-assessment/anonymized")}
          className="flex flex-col items-center gap-3 w-56 p-8 border-2 border-purple-200 rounded-2xl bg-purple-50 hover:bg-purple-100 hover:border-purple-400 transition-all text-left group">
          <span className="text-4xl">🔒</span>
          <div>
            <p className="font-bold text-purple-800 text-base">Anonymized File</p>
            <p className="text-xs text-purple-600 mt-1">Validate that the privacy-protected dataset meets your risk threshold</p>
          </div>
        </button>
        <button
          onClick={() => navigate("/risk-assessment/comparison")}
          className="flex flex-col items-center gap-3 w-56 p-8 border-2 border-teal-200 rounded-2xl bg-teal-50 hover:bg-teal-100 hover:border-teal-400 transition-all text-left group">
          <span className="text-4xl">⚖️</span>
          <div>
            <p className="font-bold text-teal-800 text-base">Comparison</p>
            <p className="text-xs text-teal-600 mt-1">Compare original vs anonymized datasets and measure privacy improvement</p>
          </div>
        </button>
      </div>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <AppLayout />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
