import React, { useState } from 'react';
import { 
  Mail, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Link2, 
  Send, 
  FileText, 
  CheckCircle,
  ExternalLink,
  Flame
} from 'lucide-react';
import { api } from '../services/api';
import { PhishingAnalysisResult } from '../types';
import { getSeverityBadgeClass } from '../utils/helpers';

export const PhishingAnalyzer: React.FC = () => {
  const [sender, setSender] = useState('security-alert@micros0ft-account-support.xyz');
  const [subject, setSubject] = useState('ACTION REQUIRED: Your Microsoft 365 Account Will Be Suspended');
  const [body, setBody] = useState(
    'Dear Employee,\n\nWe detected unauthorized access to your mailbox from an unrecognized IP in Moscow. Your account will be permanently suspended within 24 hours unless you verify your identity.\n\nPlease click here immediately to verify credentials and update your password: http://185.220.101.5/microsoft-login.php\n\nIT Support Team\nMicrosoft Corporation'
  );
  const [spfStatus, setSpfStatus] = useState('fail');
  const [dmarcStatus, setDmarcStatus] = useState('fail');

  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<PhishingAnalysisResult | null>(null);
  const [quarantined, setQuarantined] = useState(false);

  // Pre-configured attack templates
  const templates = [
    {
      name: 'M365 Credential Phish',
      sender: 'admin-portal@micros0ft-365.xyz',
      subject: 'URGENT: Password Expired - Verify Microsoft Login',
      body: 'Your network password expired today. Click here to verify credentials: http://45.33.32.156/msft/login or your account will be suspended in 2 hours.',
      spf: 'fail',
      dmarc: 'fail'
    },
    {
      name: 'Executive Wire Fraud (BEC)',
      sender: 'ceo-direct@executive-mail.org',
      subject: 'Urgent Wire Transfer Request - Confidential Acquisition',
      body: 'Please process an immediate wire transfer of $84,500 to vendor account before 5 PM today. Final notice before contract penalty. Details attached.',
      spf: 'softfail',
      dmarc: 'pass'
    },
    {
      name: 'IRS / Tax Refund Scams',
      sender: 'refunds@irs-tax-gov.buzz',
      subject: 'Notice: Unclaimed Tax Refund Payment Pending Approval',
      body: 'IRS has approved your tax refund of $1,420. Submit your SSN and bank details at http://198.51.100.42/refund-claim immediately.',
      spf: 'fail',
      dmarc: 'fail'
    },
    {
      name: 'Benign Corporate Digest',
      sender: 'sprint-bot@enterprise.org',
      subject: 'Weekly Engineering Sprint Retrospective Notes',
      body: 'Hi Team,\nHere is the weekly sprint digest. We closed 18 tickets and deployed the threat detection pipeline v2. Have a great weekend!\nCheers,\nSarah',
      spf: 'pass',
      dmarc: 'pass'
    }
  ];

  const handleAnalyze = async () => {
    setIsLoading(true);
    setQuarantined(false);
    try {
      const res = await api.analyzeEmail({
        sender,
        subject,
        body,
        headers: { spf: spfStatus, dmarc: dmarcStatus }
      });
      setResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const loadTemplate = (tmpl: typeof templates[0]) => {
    setSender(tmpl.sender);
    setSubject(tmpl.subject);
    setBody(tmpl.body);
    setSpfStatus(tmpl.spf);
    setDmarcStatus(tmpl.dmarc);
    setResult(null);
    setQuarantined(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Mail className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white font-mono">
              AI Phishing Email Detection & Semantic Analyzer
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Combines NLP semantic classification (TF-IDF + Logistic Regression) with domain reputation, SPF/DMARC validation, and heuristic URL risk scoring.
          </p>
        </div>

        {/* Quick Load Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-mono text-slate-500 mr-1">Load Template:</span>
          {templates.map((t, idx) => (
            <button
              key={idx}
              onClick={() => loadTemplate(t)}
              className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              {t.name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Email Input Panel */}
        <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h3 className="text-sm font-bold text-white font-mono flex items-center space-x-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Inbound Email Message Telemetry</span>
          </h3>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <label className="text-slate-400">Sender Address (From:):</label>
              <input
                type="text"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-slate-400">Subject Line:</label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400">SPF Authentication:</label>
                <select
                  value={spfStatus}
                  onChange={(e) => setSpfStatus(e.target.value)}
                  className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="pass">PASS (Aligned)</option>
                  <option value="fail">FAIL (Forged / Spoofed)</option>
                  <option value="softfail">SOFTFAIL (Unlisted IP)</option>
                </select>
              </div>
              <div>
                <label className="text-slate-400">DMARC Policy Check:</label>
                <select
                  value={dmarcStatus}
                  onChange={(e) => setDmarcStatus(e.target.value)}
                  className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="pass">PASS</option>
                  <option value="fail">FAIL</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-slate-400">Email Body & Hyperlinks:</label>
              <textarea
                rows={7}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleAnalyze}
              disabled={isLoading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center space-x-2"
            >
              {isLoading ? (
                <span>Running NLP & Heuristic Inference...</span>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>Execute AI Phishing Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* AI Diagnostics & Report Panel */}
        <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h3 className="text-sm font-bold text-white font-mono flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>AI Risk Scoring & Threat Diagnostics</span>
          </h3>

          {!result ? (
            <div className="h-96 flex flex-col items-center justify-center text-slate-500 space-y-2 border border-dashed border-slate-800 rounded-lg p-6 font-mono text-center">
              <Mail className="w-10 h-10 text-slate-600" />
              <p className="text-xs">
                Click "Execute AI Phishing Analysis" or select a template above to generate real-time threat diagnostics.
              </p>
            </div>
          ) : (
            <div className="space-y-4 font-mono text-xs">
              {/* Score Meter */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-[11px] text-slate-400 uppercase tracking-wider">
                    Composite Phishing Risk Score
                  </span>
                  <div className="flex items-baseline space-x-3 mt-1">
                    <span
                      className={`text-3xl font-bold ${
                        result.phishing_score >= 0.70
                          ? 'text-red-400'
                          : result.phishing_score >= 0.40
                          ? 'text-yellow-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {(result.phishing_score * 100).toFixed(1)}%
                    </span>
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${getSeverityBadgeClass(
                        result.threat_level
                      )}`}
                    >
                      {result.threat_level} RISK
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-slate-500 text-[10px]">NLP Classifier Confidence:</span>
                  <p className="text-cyan-400 font-bold text-sm">
                    {(result.ml_confidence * 100).toFixed(1)}%
                  </p>
                </div>
              </div>

              {/* Detected Indicators */}
              <div className="space-y-2">
                <span className="text-slate-400 font-bold text-[11px] uppercase tracking-wider">
                  Threat Indicators Identified:
                </span>

                {result.indicators.detected_urgency_triggers.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300">
                    <span className="font-bold flex items-center space-x-1.5 mb-1">
                      <Flame className="w-3.5 h-3.5 text-red-400" />
                      <span>Psychological Urgency Triggers:</span>
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {result.indicators.detected_urgency_triggers.map((t, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-red-900/40 text-red-200 text-[10px]">
                          "{t}"
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {result.indicators.credential_harvesting_cues.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300">
                    <span className="font-bold flex items-center space-x-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      <span>Credential Harvesting Patterns:</span>
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {result.indicators.credential_harvesting_cues.map((c, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-amber-900/40 text-amber-200 text-[10px]">
                          "{c}"
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {result.indicators.sender_flags.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-300">
                    <span className="font-bold mb-1 block">Sender / Header Anomalies:</span>
                    <ul className="list-disc list-inside space-y-0.5 text-slate-300 text-[11px]">
                      {result.indicators.sender_flags.map((f, idx) => (
                        <li key={idx}>{f}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.indicators.urls_scanned.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                    <span className="font-bold text-slate-300 flex items-center space-x-1.5">
                      <Link2 className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Extracted URL Diagnostics:</span>
                    </span>
                    {result.indicators.urls_scanned.map((u, idx) => (
                      <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800/80 space-y-1">
                        <span className="text-cyan-400 break-all">{u.url}</span>
                        <div className="flex items-center space-x-2 text-[10px]">
                          <span className="text-slate-400">Risk:</span>
                          <span className="text-red-400 font-bold">{u.risk_score * 100}%</span>
                          {u.reasons.map((r, i) => (
                            <span key={i} className="text-amber-400">({r})</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* SOC Playbook Recommendations & Quarantine Action */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-slate-400 font-bold uppercase text-[10px] tracking-wider">
                  Automated SOC Mitigation Playbook:
                </span>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  {result.soc_recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>

                {result.is_phishing && (
                  <div className="pt-2">
                    <button
                      onClick={() => setQuarantined(true)}
                      disabled={quarantined}
                      className={`w-full py-2 rounded-lg text-xs font-bold transition-all ${
                        quarantined
                          ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/40'
                          : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-500/20'
                      }`}
                    >
                      {quarantined ? '✓ Message Quarantined & Sender Blocked in Gateway' : '🚨 Execute Immediate Enterprise Quarantine'}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
