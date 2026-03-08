export default function Features() {
  return (
    <section id="features" className="features">
      <div className="container">
        <h2 className="section-title">
          Why <span className="text-gradient">Chaos Kitten?</span>
        </h2>
      </div>

      <div className="feature-scroller">
        <div className="feature-track">
          {/* Original Cards */}
          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-cyan">
              <i className="fas fa-file-code"></i>
            </div>
            <h3>OpenAPI Parsing</h3>
            <p>
              Forget manual configuration. Chaos Kitten natively parses your{" "}
              <strong>Swagger/OpenAPI</strong> specs to map every endpoint.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-magenta">
              <i className="fas fa-brain"></i>
            </div>
            <h3>AI Attack Planning</h3>
            <p>
              Powered by LLMs, the brain understands business logic constraints
              and generates <strong>context-aware</strong> payloads.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-purple">
              <i className="fas fa-chart-pie"></i>
            </div>
            <h3>Automated Reporting</h3>
            <p>
              Get instant, actionable insights. Reports are generated in{" "}
              <strong>HTML, JSON, and SARIF</strong> formats.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-yellow">
              <i className="fas fa-mask"></i>
            </div>
            <h3>XSS Validation</h3>
            <p>
              Validates Reflected XSS attacks using a headless browser to ensure
              vulnerabilities are <strong>exploitable</strong>.
            </p>
          </div>

          {/* Duplicated Cards for Infinite Scroll */}
          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-cyan">
              <i className="fas fa-file-code"></i>
            </div>
            <h3>OpenAPI Parsing</h3>
            <p>
              Forget manual configuration. Chaos Kitten natively parses your{" "}
              <strong>Swagger/OpenAPI</strong> specs to map every endpoint.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-magenta">
              <i className="fas fa-brain"></i>
            </div>
            <h3>AI Attack Planning</h3>
            <p>
              Powered by LLMs, the brain understands business logic constraints
              and generates <strong>context-aware</strong> payloads.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-purple">
              <i className="fas fa-chart-pie"></i>
            </div>
            <h3>Automated Reporting</h3>
            <p>
              Get instant, actionable insights. Reports are generated in{" "}
              <strong>HTML, JSON, and SARIF</strong> formats.
            </p>
          </div>

          <div className="feature-card glass-panel">
            <div className="card-glow"></div>
            <div className="icon-box icon-yellow">
              <i className="fas fa-mask"></i>
            </div>
            <h3>XSS Validation</h3>
            <p>
              Validates Reflected XSS attacks using a headless browser to ensure
              vulnerabilities are <strong>exploitable</strong>.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
