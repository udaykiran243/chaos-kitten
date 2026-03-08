"use client";

import Link from "next/link";
import Image from "next/image";

export default function Page() {
  return (
    <>
      <style jsx global>{`
:root {
            --bg-main: #050712;
            --bg-card: #0c0f1b;
            --bg-card-soft: #111525;
            --accent-pink: #ff3b9a;
            --accent-purple: #7b5cff;
            --accent-cyan: #21e6ff;
            --accent-yellow: #ffd66b;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --border-subtle: rgba(148, 163, 184, 0.2);
            --radius-lg: 18px;
            --shadow-card: 0 24px 60px rgba(0, 0, 0, 0.65);
            --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text",
                "Segoe UI", Roboto, sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-sans);
            background: radial-gradient(circle at top left, #1a1037 0, #050712 45%),
                radial-gradient(circle at bottom right, #071e33 0, #050712 55%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 24px 12px 40px;
        }

        .shell {
            max-width: 900px;
            margin: 0 auto;
        }

        /* Top bar with Go Back button */
        .top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
        }

        .back-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.4);
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            text-decoration: none;
        }

        .back-btn:hover {
            background: rgba(31, 41, 55, 0.95);
            color: #e5e7eb;
        }

        .back-btn span.icon {
            font-size: 14px;
            transform: translateY(0.5px);
        }

        /* Header */
        header.page-header {
            text-align: center;
            margin-bottom: 40px;
        }

        .page-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 12px;
            border-radius: 999px;
            background: rgba(255, 59, 154, 0.1);
            border: 1px solid rgba(255, 59, 154, 0.35);
            font-size: 12px;
            color: #f9a8d4;
            margin-bottom: 16px;
        }

        .page-title {
            font-size: clamp(2rem, 4vw, 2.5rem);
            line-height: 1.2;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 12px;
            background: linear-gradient(90deg, #22e6ff, #ff3b9a);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .page-subtitle {
            color: var(--text-secondary);
            font-size: 14px;
            max-width: 600px;
            margin: 0 auto;
        }

        .last-updated {
            display: inline-block;
            margin-top: 12px;
            padding: 4px 10px;
            background: rgba(15, 23, 42, 0.85);
            border-radius: 6px;
            font-size: 11px;
            color: var(--text-secondary);
            border: 1px solid rgba(55, 65, 81, 0.6);
        }

        /* Content panel */
        .content-panel {
            background: linear-gradient(145deg, #0b1020, #050816);
            border-radius: var(--radius-lg);
            padding: 32px 28px;
            border: 1px solid var(--border-subtle);
            box-shadow: var(--shadow-card);
        }

        .section {
            margin-bottom: 32px;
        }

        .section:last-child {
            margin-bottom: 0;
        }

        .section-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-primary);
        }

        .section-title .icon {
            font-size: 20px;
        }

        .section-content p {
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.7;
            margin-bottom: 12px;
        }

        .section-content ul {
            list-style: none;
            padding-left: 0;
            margin: 12px 0;
        }

        .section-content li {
            font-size: 14px;
            color: var(--text-secondary);
            padding-left: 24px;
            position: relative;
            margin-bottom: 8px;
            line-height: 1.6;
        }

        .section-content li::before {
            content: "▹";
            position: absolute;
            left: 0;
            color: var(--accent-cyan);
            font-size: 14px;
        }

        .highlight-box {
            background: rgba(34, 197, 94, 0.08);
            border: 1px solid rgba(34, 197, 94, 0.25);
            border-radius: 12px;
            padding: 16px;
            margin: 16px 0;
        }

        .highlight-box p {
            margin: 0;
            font-size: 13px;
            color: #86efac;
        }

        .warning-box {
            background: rgba(251, 146, 60, 0.08);
            border: 1px solid rgba(251, 146, 60, 0.25);
            border-radius: 12px;
            padding: 16px;
            margin: 16px 0;
        }

        .warning-box p {
            margin: 0;
            font-size: 13px;
            color: #fdba74;
        }

        .danger-box {
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 12px;
            padding: 16px;
            margin: 16px 0;
        }

        .danger-box p {
            margin: 0;
            font-size: 13px;
            color: #fca5a5;
        }

        code {
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
                Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            background: rgba(15, 23, 42, 0.85);
            padding: 2px 6px;
            border-radius: 6px;
            border: 1px solid rgba(148, 163, 184, 0.35);
            color: #e5e7eb;
        }

        a {
            color: var(--accent-cyan);
            text-decoration: none;
            transition: color 0.2s;
        }

        a:hover {
            color: #fff;
            text-decoration: underline;
        }

        /* Mobile tweaks */
        @media (max-width: 768px) {
            body {
                padding: 18px 10px 32px;
            }

            .content-panel {
                padding: 24px 18px;
            }

            .page-title {
                font-size: 1.8rem;
            }
        }
      `}</style>
      <div>
<div className="shell">
        {/* Top bar with Go Back button */}
        <div className="top-bar">
            <button className="back-btn" onClick={() => window.history.back()}>
                <span className="icon">←</span>
                <span>Go back</span>
            </button>
        </div>

        {/* Header */}
        <header className="page-header">
            <div className="page-badge">⚖️ Legal Agreement</div>
            <h1 className="page-title">Terms of Service</h1>
            <p className="page-subtitle">
                Legal terms for using Chaos Kitten, the open-source API security scanner
            </p>
            <span className="last-updated">Effective: March 4, 2026</span>
        </header>

        {/* Main content */}
        <div className="content-panel">
            {/* Acceptance of Terms */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">📜</span>
                    1. Acceptance of Terms
                </h2>
                <div className="section-content">
                    <p>
                        By downloading, installing, or using Chaos Kitten (the "Software"), you agree to be bound by
                        these Terms of Service ("Terms"). If you do not agree, do not use the Software.
                    </p>
                    <p>
                        These Terms apply to all users, contributors, and organizations using Chaos Kitten for any
                        purpose.
                    </p>
                </div>
            </div>

            {/* License Grant */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">📄</span>
                    2. License Grant
                </h2>
                <div className="section-content">
                    <p>
                        Chaos Kitten is provided under the <strong>MIT License</strong>. You are granted a worldwide,
                        non-exclusive, royalty-free license to:
                    </p>
                    <ul>
                        <li>Use, copy, modify, merge, publish, distribute, sublicense, and sell copies of the Software
                        </li>
                        <li>Use the Software for commercial and non-commercial purposes</li>
                        <li>Distribute modified versions under compatible licenses</li>
                    </ul>
                    <p>
                        See the <a href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/LICENSE"
                            target="_blank" rel="noopener noreferrer">LICENSE</a> file for complete terms.
                    </p>
                </div>
            </div>

            {/* Authorized Use */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">✅</span>
                    3. Authorized Use
                </h2>
                <div className="section-content">
                    <p>
                        You may use Chaos Kitten to test APIs that you:
                    </p>
                    <ul>
                        <li>Own or operate</li>
                        <li>Have explicit written permission to test</li>
                        <li>Are contractually authorized to perform security assessments on</li>
                    </ul>
                    <div className="highlight-box">
                        <p>
                            <strong>✓ Examples of authorized use:</strong> Testing your company's staging API,
                            pentesting with client authorization, bug bounty programs with explicit scope.
                        </p>
                    </div>
                </div>
            </div>

            {/* Prohibited Use */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">🚫</span>
                    4. Prohibited Use
                </h2>
                <div className="section-content">
                    <p>
                        You <strong>MAY NOT</strong> use Chaos Kitten to:
                    </p>
                    <ul>
                        <li>Test APIs without explicit authorization</li>
                        <li>Access systems without permission (violating CFAA or similar laws)</li>
                        <li>Conduct denial-of-service attacks or impair service availability</li>
                        <li>Extract or steal data from unauthorized systems</li>
                        <li>Violate applicable laws or regulations</li>
                        <li>Use in malware, ransomware, or other malicious software</li>
                    </ul>

                    <div className="danger-box">
                        <p>
                            <strong>⚠️ Legal Risk:</strong> Unauthorized security testing is illegal in most
                            jurisdictions and may result in criminal prosecution.
                        </p>
                    </div>
                </div>
            </div>

            {/* No Warranty */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">⚠️</span>
                    5. No Warranty
                </h2>
                <div className="section-content">
                    <p>
                        Chaos Kitten is provided "AS IS" and "AS AVAILABLE" without warranties of any kind, either
                        express or implied, including but not limited to:
                    </p>
                    <ul>
                        <li>Merchantability, fitness for a particular purpose, or non-infringement</li>
                        <li>Error-free operation or uninterrupted use</li>
                        <li>Complete vulnerability detection (false negatives possible)</li>
                        <li>Compatibility with future versions or third-party services</li>
                    </ul>
                    <p>
                        Security testing tools may produce false positives or miss vulnerabilities. Always validate
                        findings manually.
                    </p>
                </div>
            </div>

            {/* Limitation of Liability */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">🛡️</span>
                    6. Limitation of Liability
                </h2>
                <div className="section-content">
                    <p>
                        To the maximum extent permitted by law, the Chaos Kitten project maintainers, contributors, and
                        affiliates shall not be liable for:
                    </p>
                    <ul>
                        <li>Any indirect, incidental, special, consequential, or punitive damages</li>
                        <li>Loss of profits, revenue, data, or goodwill</li>
                        <li>Damage caused by unauthorized use of the Software</li>
                        <li>Legal consequences of misuse or unauthorized testing</li>
                        <li>Third-party service failures (LLM providers, CI/CD platforms)</li>
                    </ul>
                    <p>
                        Total liability shall not exceed $100 USD or the amount you paid for the Software (zero for open
                        source).
                    </p>
                </div>
            </div>

            {/* Third-Party Services */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">🔗</span>
                    7. Third-Party Services
                </h2>
                <div className="section-content">
                    <p>
                        Chaos Kitten integrates with third-party services including:
                    </p>
                    <ul>
                        <li><strong>LLM Providers:</strong> Anthropic Claude, OpenAI GPT – Subject to their Terms of
                            Service</li>
                        <li><strong>Browser Automation:</strong> Playwright/Chromium – Local execution only</li>
                        <li><strong>CI/CD Platforms:</strong> GitHub Actions, GitLab CI – Subject to platform terms</li>
                    </ul>
                    <p>
                        You are responsible for complying with all third-party terms and managing your API keys
                        securely.
                    </p>
                </div>
            </div>

            {/* Contributions */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">🤝</span>
                    8. Contributions
                </h2>
                <div className="section-content">
                    <p>
                        Contributions to Chaos Kitten are welcome under the MIT License. By submitting code, issues, or
                        documentation, you:
                    </p>
                    <ul>
                        <li>Grant a perpetual, worldwide license to the project</li>
                        <li>Warrant that your contribution is original and doesn't infringe third-party rights</li>
                        <li>Agree to follow the <a
                                href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/CONTRIBUTING.md"
                                target="_blank" rel="noopener noreferrer">Contributor Guidelines</a></li>
                    </ul>
                </div>
            </div>

            {/* Intellectual Property */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">©</span>
                    9. Intellectual Property
                </h2>
                <div className="section-content">
                    <p>
                        "Chaos Kitten" and related trademarks are owned by the project maintainers. You may use the name
                        for attribution but not in a way that implies endorsement or affiliation.
                    </p>
                    <p>
                        All contributions become part of the open-source project under the MIT License.
                    </p>
                </div>
            </div>

            {/* Termination */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">⏹️</span>
                    10. Termination
                </h2>
                <div className="section-content">
                    <p>
                        We may suspend or terminate access to Chaos Kitten if you:
                    </p>
                    <ul>
                        <li>Violate these Terms or applicable laws</li>
                        <li>Engage in abusive or harmful conduct</li>
                        <li>Repeatedly infringe third-party rights</li>
                    </ul>
                    <p>
                        Open-source licenses are perpetual and irrevocable once granted.
                    </p>
                </div>
            </div>

            {/* Governing Law */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">⚖️</span>
                    11. Governing Law
                </h2>
                <div className="section-content">
                    <p>
                        These Terms are governed by the laws of India, without regard to conflict of law principles. Any
                        disputes shall be resolved exclusively in the courts of Pune, Maharashtra, India.
                    </p>
                </div>
            </div>

            {/* Changes to Terms */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">📝</span>
                    12. Changes to Terms
                </h2>
                <div className="section-content">
                    <p>
                        We may update these Terms at any time. Changes will be posted to:
                    </p>
                    <ul>
                        <li>This page (with updated "Effective" date)</li>
                        <li><a href="https://github.com/mdhaarishussain/chaos-kitten" target="_blank" rel="noopener noreferrer">GitHub
                                repository</a></li>
                    </ul>
                    <p>
                        Continued use after changes constitutes acceptance of the revised Terms.
                    </p>
                </div>
            </div>

            {/* Contact */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">📧</span>
                    13. Contact Information
                </h2>
                <div className="section-content">
                    <p>
                        Questions about these Terms? Contact:
                    </p>
                    <ul>
                        <li><strong>GitHub Issues:</strong> <a
                                href="https://github.com/mdhaarishussain/chaos-kitten/issues"
                                target="_blank" rel="noopener noreferrer">github.com/mdhaarishussain/chaos-kitten/issues</a></li>
                        <li><strong>Discussions:</strong> <a
                                href="https://github.com/mdhaarishussain/chaos-kitten/discussions"
                                target="_blank" rel="noopener noreferrer">github.com/mdhaarishussain/chaos-kitten/discussions</a></li>
                        <li><strong>Maintainer:</strong> <a href="https://github.com/mdhaarishussain"
                                target="_blank" rel="noopener noreferrer">@mdhaarishussain</a></li>
                    </ul>
                </div>
            </div>

            {/* Acknowledgment */}
            <div className="section">
                <h2 className="section-title">
                    <span className="icon">✍️</span>
                    14. Acknowledgment
                </h2>
                <div className="section-content">
                    <p>
                        By using Chaos Kitten, you acknowledge that you have read, understood, and agree to be bound by
                        these Terms of Service.
                    </p>
                    <div className="highlight-box">
                        <p>
                            <strong>⚡ Quick Summary:</strong> Use responsibly, get authorization for testing, no
                            warranties, MIT License, don't break the law.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
      </div>
    </>
  );
}
