const highlights = [
  {
    title: "AI-Enabled Platforms",
    detail:
      "Architected AI-native operations platforms, hybrid cloud control planes, and autonomous remediation systems."
  },
  {
    title: "Leadership + Growth",
    detail:
      "Instrumental in scaling telecom operations from 65 to 1,200+ employees and guiding teams through multiple successful exits."
  },
  {
    title: "Mentorship + Clarity",
    detail:
      "Mentored teams in WAN networking, information security, expert testimony, and full-stack engineering, translating complex concepts for non-technical audiences."
  }
];

export default function About() {
  return (
    <section className="section about">
      <div className="about-hero">
        <div>
          <p className="eyebrow">About Xyence</p>
          <h1>Joshua Restivo</h1>
          <p className="lead">
            Joshua Restivo is the founder of Xyence, a platform consulting firm
            focused on AI-enabled operations, cloud control planes, and durable
            engineering systems. For more than 25 years, he has worked at the
            intersection of infrastructure, automation, and complex systems —
            helping organizations modernize environments, build AI-native
            platforms, and bring high-stakes products to market.
          </p>
          <p className="lead">
            He lives in downtown St. Louis inside the City Museum — not near it,
            not inspired by it, but inside it: a giant, climbable, welded,
            reclaimed architectural dreamscape where art is also structure and
            structure is also play. It’s an unusual place to call home, but it
            fits: Joshua has always been drawn to systems that are alive —
            layered, expressive, intricate, and unapologetically real.
          </p>
          <p className="lead">
            At night, when he drives back into the City from across the river,
            he watches the skyline gather itself into clarity — brighter,
            closer, inevitable. The feeling is part awe and part belonging. To
            him, cities are proof that complexity doesn’t have to be cold.
            They’re the most ambitious machines humans have ever built:
            networks of movement, logistics, story, resilience, failure,
            adaptation, and reinvention — all running at once.
          </p>
          <p className="lead">That worldview shows up in his work.</p>
          <p className="lead">
            Joshua has led platform initiatives across large environments like
            AT&T and Savvis/CenturyLink, and in startups spanning computer
            forensics, cloud orchestration, and advanced network engineering.
            Most recently, he architected Z1N — a Kubernetes-native, multi-tenant
            operations platform that unifies AI agents, orchestration engines,
            ERP-class workflows, and telecom automation across hybrid cloud
            systems. He has also built AIOps reasoning pipelines and enterprise
            API control planes designed to endure high transaction volume,
            operational chaos, and constant change.
          </p>
          <p className="lead">
            He’s known for translating complex technical systems into language
            that makes sense to business leaders, community stakeholders, and
            classrooms — and has delivered training to U.S. state and federal
            law enforcement agents and attorneys. His work has supported
            municipalities and charitable organizations through IT-focused
            volunteer initiatives, and is cited in Jose Baez’s New York Times
            best-selling book, <em>Presumed Guilty</em>.
          </p>
          <p className="lead">
            At the center of all of it is a single belief: the systems we build
            aren’t just technical — they’re cultural. They reveal what we value,
            what we tolerate, and what we’re willing to make durable. Joshua
            builds platforms the way he loves cities: layered, resilient,
            intelligently orchestrated — and capable of holding the full
            complexity of real life.
          </p>
        </div>
        <div className="about-card">
          <img src="/josh-restivo.jpg" alt="Joshua Restivo" />
          <div>
            <h3>Founder · Principal Systems Architect</h3>
            <p>
              Specialties: AI-enabled platforms, Kubernetes/GitOps, hybrid cloud
              operations, telecom automation, platform governance, and
              executive technical leadership.
            </p>
          </div>
        </div>
      </div>

      <div className="cards">
        {highlights.map((highlight) => (
          <article key={highlight.title} className="card">
            <h3>{highlight.title}</h3>
            <p>{highlight.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
