"use client";

import { useState } from 'react';

export default function Quickstart() {
  const [copied, setCopied] = useState(false);
  const code = `# Install from PyPI (Coming soon)
git clone https://github.com/mdhaarishussain/chaos-kitten.git
cd chaos-kitten
pip install -e .

# Configure your environment
export ANTHROPIC_API_KEY=your_key_here

# Run a scan
chaos-kitten scan --target http://localhost:5000 --spec openapi.json`;

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <section id="quickstart" className="quickstart">
      <div className="container">
        <div className="quickstart-content">
          <h2 className="section-title">Ready to pounce?</h2>
          <p>
            Install Chaos Kitten via pip and start your first scan in seconds.
          </p>

          <div className="code-block">
            <button 
              className="copy-btn" 
              onClick={handleCopy} 
              style={copied ? { color: '#27c93f' } : undefined}
            >
              {copied ? <i className="fas fa-check"></i> : <i className="far fa-copy"></i>}
            </button>
            <pre>
              <code id="install-code">{code}</code>
            </pre>
          </div>

          <div className="btn-group">
            <a
              href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/README.md"
              target="_blank"
              className="btn btn-primary"
            >
              Read Full Documentation
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
