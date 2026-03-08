"use client";

import { useEffect, useState } from "react";
import Navbar from "@/components/Navbar";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import { Shield, KeyRound, Lock, Copy, CheckCircle2, AlertTriangle } from "lucide-react";

export default function SecuritySettingsPage() {
  const { user, hydrate, setUser } = useAuthStore();
  const [mfaStatus, setMfaStatus] = useState<{ mfa_enabled: boolean; mfa_setup_complete: boolean } | null>(null);
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; qr_uri: string } | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(true);
  const [savingPassword, setSavingPassword] = useState(false);
  const [workingMfa, setWorkingMfa] = useState(false);

  const loadStatus = async () => {
    try {
      const [me, status] = await Promise.all([api.me(), api.mfaStatus()]);
      setUser(me);
      setMfaStatus(status);
    } catch (e: any) {
      toast.error(e.message || "Failed to load security settings");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  useEffect(() => {
    if (user) {
      loadStatus();
    } else {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const startMfaSetup = async () => {
    setWorkingMfa(true);
    try {
      const res = await api.mfaSetup();
      setMfaSetup(res);
      toast.success("MFA secret generated");
    } catch (e: any) {
      toast.error(e.message || "Failed to start MFA setup");
    } finally {
      setWorkingMfa(false);
    }
  };

  const completeMfaSetup = async () => {
    if (!mfaCode.trim()) return;
    setWorkingMfa(true);
    try {
      await api.mfaVerify(mfaCode.trim());
      toast.success("MFA enabled");
      setMfaSetup(null);
      setMfaCode("");
      await loadStatus();
    } catch (e: any) {
      toast.error(e.message || "Failed to verify MFA");
    } finally {
      setWorkingMfa(false);
    }
  };

  const disableMfa = async () => {
    if (!disableCode.trim()) return;
    setWorkingMfa(true);
    try {
      await api.mfaDisable(disableCode.trim());
      toast.success("MFA disabled");
      setDisableCode("");
      setMfaSetup(null);
      await loadStatus();
    } catch (e: any) {
      toast.error(e.message || "Failed to disable MFA");
    } finally {
      setWorkingMfa(false);
    }
  };

  const changePassword = async () => {
    setSavingPassword(true);
    try {
      await api.changeMyPassword(currentPassword, newPassword);
      toast.success("Password updated");
      setCurrentPassword("");
      setNewPassword("");
    } catch (e: any) {
      toast.error(e.message || "Failed to update password");
    } finally {
      setSavingPassword(false);
    }
  };

  if (!user) return null;

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-primary)" }}>
      <Navbar />
      <div className="max-w-4xl mx-auto p-6 space-y-6">
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
            <Shield className="w-5 h-5 text-indigo-400" /> Security Settings
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Manage your account protection, password, and MFA configuration.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                <KeyRound className="w-4 h-4 text-emerald-400" /> Multi-Factor Authentication
              </h2>
              {!loading && (
                <span className={`text-xs px-2 py-0.5 rounded-full ${mfaStatus?.mfa_enabled ? "text-emerald-400 bg-emerald-500/10" : "text-amber-400 bg-amber-500/10"}`}>
                  {mfaStatus?.mfa_enabled ? "Enabled" : "Disabled"}
                </span>
              )}
            </div>

            {!mfaStatus?.mfa_enabled && !mfaSetup && (
              <div className="space-y-3">
                <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  MFA is currently disabled for your account. Enable it to require a one-time code during sign-in.
                </p>
                <button onClick={startMfaSetup} disabled={workingMfa} className="btn-primary text-sm py-2 px-4 disabled:opacity-50">
                  {workingMfa ? "Preparing..." : "Set Up MFA"}
                </button>
              </div>
            )}

            {mfaSetup && (
              <div className="space-y-3">
                <div className="rounded-lg border p-3 text-xs" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
                  <p className="font-medium mb-2" style={{ color: "var(--text-primary)" }}>Authenticator secret</p>
                  <div className="flex items-start gap-2">
                    <code className="break-all flex-1">{mfaSetup.secret}</code>
                    <button
                      onClick={async () => {
                        await navigator.clipboard.writeText(mfaSetup.secret);
                        toast.success("Secret copied");
                      }}
                      className="p-1.5 rounded hover:bg-white/10"
                      title="Copy secret"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <p className="mt-2">Use the secret or otpauth URI below in Google Authenticator, Microsoft Authenticator, or another TOTP app.</p>
                  <code className="mt-2 block break-all">{mfaSetup.qr_uri}</code>
                </div>

                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Verification code</label>
                  <input
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder="123456"
                    className="input-field py-2 text-sm w-full"
                  />
                </div>
                <button onClick={completeMfaSetup} disabled={workingMfa || !mfaCode.trim()} className="btn-primary text-sm py-2 px-4 disabled:opacity-50">
                  {workingMfa ? "Verifying..." : "Enable MFA"}
                </button>
              </div>
            )}

            {mfaStatus?.mfa_enabled && (
              <div className="space-y-3">
                <div className="rounded-lg border p-3 text-sm flex items-start gap-2" style={{ borderColor: "rgba(16,185,129,0.2)", background: "rgba(16,185,129,0.08)", color: "#34d399" }}>
                  <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>MFA is active on your account.</span>
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Enter current MFA code to disable</label>
                  <input
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value)}
                    placeholder="123456"
                    className="input-field py-2 text-sm w-full"
                  />
                </div>
                <button onClick={disableMfa} disabled={workingMfa || !disableCode.trim()} className="btn-secondary text-sm py-2 px-4 disabled:opacity-50">
                  {workingMfa ? "Disabling..." : "Disable MFA"}
                </button>
              </div>
            )}
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-5 space-y-4">
            <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
              <Lock className="w-4 h-4 text-orange-400" /> Password
            </h2>
            <div className="rounded-lg border p-3 text-xs flex items-start gap-2" style={{ borderColor: "rgba(245,158,11,0.2)", background: "rgba(245,158,11,0.08)", color: "#fbbf24" }}>
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>Use a long, unique password. New passwords must be at least 10 characters.</span>
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>Current password</label>
              <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} className="input-field py-2 text-sm w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>New password</label>
              <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="input-field py-2 text-sm w-full" />
            </div>
            <button
              onClick={changePassword}
              disabled={savingPassword || !currentPassword || !newPassword}
              className="btn-primary text-sm py-2 px-4 disabled:opacity-50"
            >
              {savingPassword ? "Updating..." : "Change Password"}
            </button>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
