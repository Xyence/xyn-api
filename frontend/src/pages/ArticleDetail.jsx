import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

export default function ArticleDetail() {
  const { slug } = useParams();
  const [article, setArticle] = useState(null);
  const [loading, setLoading] = useState(true);
  const bodyRef = useRef(null);

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

  useEffect(() => {
    const root = bodyRef.current;
    if (!root || !window.mermaid) return;

    window.mermaid.initialize({ startOnLoad: false });

    const convertBlocks = () => {
      const blocks = root.querySelectorAll(
        "pre code.language-mermaid, pre.mermaid, code.language-mermaid"
      );
      blocks.forEach((block) => {
        if (block.dataset && block.dataset.mermaidProcessed) return;
        const text = block.textContent || "";
        const container = document.createElement("div");
        container.className = "mermaid";
        container.textContent = text.trim();
        const pre = block.closest("pre");
        if (pre) {
          pre.replaceWith(container);
        } else {
          block.replaceWith(container);
        }
        if (block.dataset) block.dataset.mermaidProcessed = "1";
      });
    };

    convertBlocks();
    const nodes = root.querySelectorAll(".mermaid");
    if (nodes.length) {
      window.mermaid.run({ nodes });
    }
  }, [article]);

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
        ref={bodyRef}
        dangerouslySetInnerHTML={{ __html: article.body }}
      />
    </section>
  );
}
