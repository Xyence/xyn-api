import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

export default function ArticleDetail() {
  const { slug } = useParams();
  const [article, setArticle] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    fetch(`${API_BASE}/api/articles/${slug}/`)
      .then((res) => res.json())
      .then((data) => {
        if (isMounted) {
          setArticle(data);
        }
      })
      .catch(() => {
        if (isMounted) {
          setArticle(null);
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
  }, [slug]);

  if (loading) {
    return (
      <section className="section">
        <p className="muted">Loading article...</p>
      </section>
    );
  }

  if (!article || article.detail) {
    return (
      <section className="section">
        <div className="empty-state">
          <p>We couldn't find that article.</p>
          <Link className="ghost" to="/articles">
            Back to articles
          </Link>
        </div>
      </section>
    );
  }

  return (
    <section className="section article-detail">
      <Link className="ghost" to="/articles">
        ← Back to articles
      </Link>
      <h1>{article.title}</h1>
      {article.summary && <p className="lead">{article.summary}</p>}
      <div
        className="rich-text"
        dangerouslySetInnerHTML={{ __html: article.body }}
      />
    </section>
  );
}
