"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import { Shield, Lock, User, Eye, EyeOff } from "lucide-react";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";

export default function LoginPage() {
  const router = useRouter();
  const { setAuth, hydrate, user } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaUserId, setMfaUserId] = useState("");

  useEffect(() => { hydrate(); }, [hydrate]);
  useEffect(() => { if (user) router.replace("/dashboard"); }, [user, router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.login(username, password);
      if (res.mfa_required) {
        setMfaRequired(true);
        setMfaUserId(res.user_id);
        toast("MFA code required", { icon: "🔐" });
      } else {
        setAuth(res.user, res.access_token);
        toast.success(`Welcome back, ${res.user.full_name}!`);
        router.push("/dashboard");
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.login(username, password, mfaCode);
      setAuth(res.user, res.access_token);
      toast.success(`Welcome back, ${res.user.full_name}!`);
      router.push("/dashboard");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "MFA verification failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background grid */}
      <div className="absolute inset-0 opacity-5"
        style={{ backgroundImage: "linear-gradient(#3B82F6 1px,transparent 1px),linear-gradient(90deg,#3B82F6 1px,transparent 1px)", backgroundSize: "50px 50px" }} />

      {/* Glowing orbs */}
      <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-blue-600 rounded-full opacity-10 blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-48 h-48 bg-purple-600 rounded-full opacity-10 blur-3xl" />

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md relative z-10"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <motion.div
            animate={{ rotate: [0, 5, -5, 0] }}
            transition={{ duration: 4, repeat: Infinity }}
            className="inline-block"
          >
            <Shield className="w-16 h-16 text-blue-500 mx-auto" />
          </motion.div>
          <h1 className="text-3xl font-bold text-white mt-3">VAPT Navigator</h1>
          <p className="text-[#9CA3AF] mt-1 text-sm">Intelligent Security Testing Platform</p>
        </div>

        <div className="card p-6">
          {!mfaRequired ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="text-sm text-[#9CA3AF] mb-1.5 block">Username</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6B7280]" />
                  <input
                    className="input-field pl-10"
                    placeholder="Enter username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoComplete="username"
                  />
                </div>
              </div>
              <div>
                <label className="text-sm text-[#9CA3AF] mb-1.5 block">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6B7280]" />
                  <input
                    className="input-field pl-10 pr-10"
                    type={showPass ? "text" : "password"}
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                  />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#6B7280] hover:text-white">
                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <motion.button
                type="submit"
                disabled={loading}
                whileTap={{ scale: 0.97 }}
                className="btn-primary w-full py-3 mt-2 disabled:opacity-50"
              >
                {loading ? "Signing in..." : "Sign In 🔐"}
              </motion.button>
              <p className="text-center text-xs text-[#6B7280] mt-2">
                Contact your administrator for access credentials.
              </p>
            </form>
          ) : (
            <form onSubmit={handleMfaVerify} className="space-y-4">
              <div className="text-center mb-2">
                <Shield className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                <p className="text-sm text-[#9CA3AF]">Enter your 6-digit authenticator code</p>
              </div>
              <div>
                <input
                  className="input-field text-center text-2xl tracking-widest"
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                  required
                  autoFocus
                />
              </div>
              <motion.button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                whileTap={{ scale: 0.97 }}
                className="btn-primary w-full py-3 disabled:opacity-50"
              >
                {loading ? "Verifying..." : "Verify MFA Code"}
              </motion.button>
              <button type="button" onClick={() => { setMfaRequired(false); setMfaCode(""); }}
                className="w-full text-sm text-[#6B7280] hover:text-white">
                Back to login
              </button>
            </form>
          )}
        </div>
      </motion.div>
    </div>
  );
}
