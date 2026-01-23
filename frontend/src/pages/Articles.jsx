import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

export default function Articles() {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    fetch(`${API_BASE}/api/articles/`)
      .then((res) => res.json())
      .then((data) => {
        if (isMounted) {
          setArticles(data);
        }
      })
      .catch(() => {
        if (isMounted) {
          setArticles([]);
        }
      })
      .finally(() => {
        if (isMounted) {
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <section className="section">
      <div className="section-head">
        <h2>Articles</h2>
        <p>Dispatches on CTO leadership, platform systems, and product velocity.</p>
      </div>

      {loading ? (
        <p className="muted">Loading articles...</p>
      ) : articles.length === 0 ? (
        <div className="empty-state">
          <p>No articles published yet.</p>
          <Link className="ghost" to="/">
            Back to home
          </Link>
        </div>
      ) : (
        <div className="cards">
          {articles.map((article) => (
            <article key={article.slug} className="card">
              <h3>{article.title}</h3>
              <p>{article.summary || "New field note from the Xyence desk."}</p>
              <Link className="ghost" to={`/articles/${article.slug}`}>
                Read article
              </Link>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
