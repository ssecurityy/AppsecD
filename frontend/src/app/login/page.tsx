"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import { ShieldCheck, Lock, User, Eye, EyeOff, ArrowRight, Smartphone, Copy, CheckCircle } from "lucide-react";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";

export default function LoginPage() {
  const router = useRouter();
  const { setAuth, hydrate, user } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);

  // MFA states
  const [mfaStep, setMfaStep] = useState<"login" | "code" | "setup">("login");
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");

  // MFA Setup states
  const [qrUri, setQrUri] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [setupLoading, setSetupLoading] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (user) router.replace("/dashboard"); }, [user, router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.login(username, password);
      if (res.needs_mfa_setup && res.mfa_token) {
        // User needs to set up MFA first (scan QR code)
        setMfaToken(res.mfa_token);
        setMfaStep("setup");
        // Fetch QR code immediately
        await fetchMfaSetup(res.mfa_token);
      } else if (res.needs_mfa && res.mfa_token) {
        // User already has MFA set up, just enter code
        setMfaToken(res.mfa_token);
        setMfaStep("code");
      } else {
        setAuth(res.user, res.access_token);
        toast.success(`Welcome back, ${res.user.full_name}`);
        router.push("/dashboard");
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const fetchMfaSetup = async (token: string) => {
    setSetupLoading(true);
    try {
      const res = await api.mfaSetupWithToken(token);
      setQrUri(res.qr_uri);
      setMfaSecret(res.secret);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to generate MFA setup");
    } finally {
      setSetupLoading(false);
    }
  };

  const handleMfaComplete = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.mfaCompleteLogin(mfaToken, mfaCode);
      setAuth(res.user, res.access_token);
      toast.success(`Welcome back, ${res.user.full_name}`);
      router.push("/dashboard");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Invalid verification code");
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSetupComplete = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.mfaCompleteSetup(mfaToken, mfaCode);
      setAuth(res.user, res.access_token);
      toast.success("MFA setup complete! Welcome.");
      router.push("/dashboard");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Invalid code. Make sure you scanned the QR code correctly.");
    } finally {
      setLoading(false);
    }
  };

  const copySecret = () => {
    navigator.clipboard.writeText(mfaSecret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const resetToLogin = () => {
    setMfaStep("login");
    setMfaToken("");
    setMfaCode("");
    setQrUri("");
    setMfaSecret("");
  };

  // Generate QR code as an image URL using a QR API
  const qrImageUrl = qrUri
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrUri)}`
    : "";

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden" style={{ background: "var(--bg-primary)" }}>
      {/* Abstract background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/20 via-transparent to-transparent" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-indigo-500/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] bg-purple-500/5 rounded-full blur-[100px]" />
        <div className="absolute inset-0 opacity-[0.02]"
          style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.1) 1px,transparent 1px)", backgroundSize: "64px 64px" }} />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className={`w-full relative z-10 ${mfaStep === "setup" ? "max-w-[480px]" : "max-w-[400px]"}`}
      >
        {/* Logo */}
        <div className="text-center mb-10">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.1, duration: 0.5 }}
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-2xl shadow-indigo-500/30 mb-4"
          >
            <ShieldCheck className="w-8 h-8 text-white" />
          </motion.div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
            AppSec<span className="text-indigo-400">D</span>
          </h1>
          <p className="mt-1.5 text-sm" style={{ color: "var(--text-muted)" }}>Enterprise Application Security Platform</p>
        </div>

        {/* Login card */}
        <div className="card-glass p-7 rounded-2xl" style={{ borderColor: "var(--border-primary)" }}>

          {/* === LOGIN FORM === */}
          {mfaStep === "login" && (
            <form onSubmit={handleLogin} className="space-y-5">
              <div>
                <label className="text-xs font-medium mb-2 block tracking-wide uppercase" style={{ color: "var(--text-muted)" }}>Username</label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
                  <input
                    className="input-field pl-10 py-3 rounded-xl"
                    placeholder="Enter username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoComplete="username"
                  />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium mb-2 block tracking-wide uppercase" style={{ color: "var(--text-muted)" }}>Password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
                  <input
                    className="input-field pl-10 pr-10 py-3 rounded-xl"
                    type={showPass ? "text" : "password"}
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                  />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-colors" style={{ color: "var(--text-muted)" }}>
                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <motion.button
                type="submit"
                disabled={loading}
                whileTap={{ scale: 0.98 }}
                className="btn-primary w-full py-3 mt-1 disabled:opacity-50 flex items-center justify-center gap-2 rounded-xl text-sm"
              >
                {loading ? (
                  <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full" />
                ) : (
                  <>Sign In <ArrowRight className="w-4 h-4" /></>
                )}
              </motion.button>
            </form>
          )}

          {/* === MFA CODE ENTRY (already set up) === */}
          {mfaStep === "code" && (
            <form onSubmit={handleMfaComplete} className="space-y-5">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 mb-3">
                  <Smartphone className="w-6 h-6 text-indigo-400" />
                </div>
                <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Two-Factor Authentication</h2>
                <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>Enter the 6-digit code from your authenticator app.</p>
              </div>
              <div>
                <label className="text-xs font-medium mb-2 block tracking-wide uppercase" style={{ color: "var(--text-muted)" }}>Verification Code</label>
                <input
                  className="input-field w-full py-3 rounded-xl text-center text-xl tracking-[0.5em] font-mono"
                  placeholder="000000"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                />
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={resetToLogin} className="btn-secondary flex-1 py-3 rounded-xl text-sm">
                  Back
                </button>
                <motion.button
                  type="submit"
                  disabled={loading || mfaCode.length !== 6}
                  whileTap={{ scale: 0.98 }}
                  className="btn-primary flex-1 py-3 rounded-xl text-sm disabled:opacity-50"
                >
                  {loading ? "Verifying..." : "Verify"}
                </motion.button>
              </div>
            </form>
          )}

          {/* === MFA SETUP (first time — scan QR code) === */}
          {mfaStep === "setup" && (
            <form onSubmit={handleMfaSetupComplete} className="space-y-5">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 mb-3">
                  <ShieldCheck className="w-6 h-6 text-emerald-400" />
                </div>
                <h2 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>Set Up Two-Factor Authentication</h2>
                <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
                  Your admin requires MFA. Scan the QR code below with your authenticator app.
                </p>
              </div>

              {setupLoading ? (
                <div className="flex justify-center py-8">
                  <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-8 h-8 border-3 border-indigo-500/30 border-t-indigo-500 rounded-full" />
                </div>
              ) : qrUri ? (
                <>
                  {/* QR Code */}
                  <div className="flex justify-center">
                    <div className="p-3 rounded-xl bg-white">
                      <img
                        src={qrImageUrl}
                        alt="Scan this QR code with your authenticator app"
                        width={180}
                        height={180}
                        className="block"
                      />
                    </div>
                  </div>

                  {/* Supported apps */}
                  <div className="flex items-center justify-center gap-3">
                    <span className="text-[10px] px-2 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">Google Authenticator</span>
                    <span className="text-[10px] px-2 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Microsoft Authenticator</span>
                  </div>

                  {/* Manual entry secret */}
                  <div className="rounded-lg p-3" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}>
                    <p className="text-[10px] uppercase tracking-wider font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>
                      Or enter this key manually:
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="text-sm font-mono flex-1 break-all" style={{ color: "var(--text-code)" }}>
                        {mfaSecret}
                      </code>
                      <button type="button" onClick={copySecret}
                        className="p-1.5 rounded-lg shrink-0 transition-all hover:bg-[var(--bg-hover)]"
                        style={{ color: copiedSecret ? "var(--accent-green)" : "var(--text-muted)" }}>
                        {copiedSecret ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Code verification */}
                  <div>
                    <label className="text-xs font-medium mb-2 block tracking-wide uppercase" style={{ color: "var(--text-muted)" }}>
                      Enter code from authenticator to verify
                    </label>
                    <input
                      className="input-field w-full py-3 rounded-xl text-center text-xl tracking-[0.5em] font-mono"
                      placeholder="000000"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                    />
                  </div>

                  <div className="flex gap-2">
                    <button type="button" onClick={resetToLogin} className="btn-secondary flex-1 py-3 rounded-xl text-sm">
                      Cancel
                    </button>
                    <motion.button
                      type="submit"
                      disabled={loading || mfaCode.length !== 6}
                      whileTap={{ scale: 0.98 }}
                      className="btn-primary flex-1 py-3 rounded-xl text-sm disabled:opacity-50"
                    >
                      {loading ? "Verifying..." : "Complete Setup"}
                    </motion.button>
                  </div>
                </>
              ) : (
                <div className="text-center py-6">
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>Failed to load QR code.</p>
                  <button type="button" onClick={() => fetchMfaSetup(mfaToken)}
                    className="text-indigo-400 text-sm mt-2 hover:underline">
                    Try again
                  </button>
                </div>
              )}
            </form>
          )}

          <p className="text-center text-[11px] mt-4" style={{ color: "var(--text-muted)" }}>
            Contact admin for access credentials
          </p>
        </div>

        {/* Footer */}
        <p className="text-center text-[10px] mt-8" style={{ color: "var(--text-muted)" }}>
          AppSecD v2.0 · Enterprise Security Platform
        </p>
      </motion.div>
    </div>
  );
}
