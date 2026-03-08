export default function Hero() {
  return (
    <section className="hero container">
      <div className="hero-content">
        <div className="badge">
          <span className="pulse"></span> v0.1.0 Alpha Release
        </div>
        <h1 className="glitch-wrapper">
          Unleash{" "}
          <span className="text-gradient glitch" data-text="Chaos">
            Chaos
          </span>{" "}
          on your <br />
          API Vulnerabilities
        </h1>
        <p className="hero-subtitle">
          The agentic AI security tool that parses OpenAPI specs, plans
          intelligent attacks, and hunts down security flaws before hackers do.
        </p>
        <div className="hero-actions">
          <a href="#quickstart" className="btn btn-primary">
            <i className="fas fa-terminal"></i> Start Hacking
          </a>
          <a
            href="https://github.com/mdhaarishussain/chaos-kitten"
            className="btn btn-outline"
          >
            <i className="fas fa-star"></i> Star Repository
          </a>
        </div>
      </div>
      <div className="hero-visual">
        <div className="terminal-window">
          <div className="terminal-header">
            <span className="dot red"></span>
            <span className="dot yellow"></span>
            <span className="dot green"></span>
            <div className="terminal-title">chaos-kitten-cli</div>
          </div>
          <div className="terminal-body">
            <div className="typing-line">
              <span className="prompt">$</span>
              <span className="typewriter">
                chaos-kitten scan --target http://api.local
              </span>
            </div>
            <div className="output delay-1">
              <span className="info">INFO</span> 🧠 Brain initializing...
            </div>
            <div className="output delay-2">
              <span className="info">INFO</span> 📋 Parsing OpenAPI spec... 12
              endpoints found.
            </div>
            <div className="output delay-3">
              <span className="warn">WARN</span> 🧠 Planning attack
              strategies...
            </div>
            <div className="output delay-4">
              <span className="success">VULN</span> 🚨 Reflected XSS found at
              GET /users
            </div>
            <div className="output delay-5">
              <span className="success">VULN</span> 🚨 SQL Injection found at
              POST /login
            </div>
            <div className="output delay-6">
              <span className="info">INFO</span> 📊 Report generated:
              reports/audit.html
            </div>
            <div className="cursor-line">
              <span className="prompt">$</span> <span className="cursor">_</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
