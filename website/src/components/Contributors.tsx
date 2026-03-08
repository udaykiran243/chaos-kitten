"use client";

import { useEffect, useState } from "react";

interface Contributor {
  login: string;
  avatar_url: string;
  html_url: string;
  contributions: number;
}

export default function Contributors() {
  const [contributors, setContributors] = useState<Contributor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    async function fetchContributors() {
      try {
        const response = await fetch(
          "https://api.github.com/repos/mdhaarishussain/chaos-kitten/contributors?per_page=100"
        );
        if (!response.ok) throw new Error("Failed to fetch");
        const data = await response.json();
        setContributors(data);
      } catch (err) {
        console.error("Error fetching contributors:", err);
        setError(true);
      } finally {
        setLoading(false);
      }
    }
    fetchContributors();
  }, []);

  return (
    <section id="contributors" className="contributors">
      <div className="container">
        <h2 className="section-title">Meet the <span className="text-gradient">Contributors</span></h2>
        <p className="contributors-subtitle">The talented people making Chaos Kitten possible</p>
        
        <div className="contributors-grid" id="contributors-grid">
            {loading ? (
                <>
                    <div className="loading-skeleton">
                        <div className="skeleton-avatar"></div>
                        <div className="skeleton-text"></div>
                        <div className="skeleton-text" style={{ width: '80%' }}></div>
                    </div>
                    <div className="loading-skeleton">
                        <div className="skeleton-avatar"></div>
                        <div className="skeleton-text"></div>
                        <div className="skeleton-text" style={{ width: '80%' }}></div>
                    </div>
                    <div className="loading-skeleton">
                        <div className="skeleton-avatar"></div>
                        <div className="skeleton-text"></div>
                        <div className="skeleton-text" style={{ width: '80%' }}></div>
                    </div>
                </>
            ) : error ? (
                <p style={{ textAlign: 'center', color: 'var(--text-muted)', gridColumn: '1/-1' }}>Failed to load contributors. Please check back later.</p>
            ) : (
                contributors.map(contributor => (
                    <div key={contributor.login} className="contributor-card">
                        <div className="contributor-avatar">
                            <img src={contributor.avatar_url} alt={contributor.login} title={contributor.login} />
                        </div>
                        <div className="contributor-name">{contributor.login}</div>
                        <div className="contributor-role">{contributor.contributions} contribution{contributor.contributions !== 1 ? 's' : ''}</div>
                        <div className="contributor-links">
                            <a href={contributor.html_url} target="_blank" rel="noopener noreferrer" className="contributor-link" title="GitHub Profile">
                                <i className="fab fa-github"></i>
                            </a>
                        </div>
                    </div>
                ))
            )}
        </div>
      </div>
    </section>
  );
}
