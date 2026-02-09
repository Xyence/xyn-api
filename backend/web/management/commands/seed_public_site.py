import textwrap
from typing import Any

from django.core.management.base import BaseCommand

from web.models import MenuItem, Page, SiteConfig, WebSection


HOME_HERO = {
    "kicker": "Xyence · Platform Consulting",
    "headline": "Build the systems that let your product and engineering teams move at exponential speed.",
    "subheadline": (
        "Xyence partners with founders and technical leaders to architect platforms, "
        "stabilize delivery, and turn ambitious roadmaps into resilient systems."
    ),
    "primaryCta": {"label": "Engage Xyence", "href": "mailto:info@xyence.io"},
    "secondaryCta": {"label": "Read the field notes", "href": "/articles"},
    "imageUrl": "/xyence-stl.png",
}

SERVICES = {
    "items": [
        {
            "title": "Fractional CTO",
            "bullets": [
                "Operational leadership and technical strategy.",
                "Delivery alignment that scales without the overhead.",
            ],
        },
        {
            "title": "Engineering Systems",
            "bullets": [
                "Team design and platform modernization.",
                "Architectural guidance to unlock sustainable velocity.",
            ],
        },
        {
            "title": "IT Architecture",
            "bullets": [
                "Secure infrastructure patterns for cloud-native products.",
                "Resilient foundations for regulated environments.",
            ],
        },
    ]
}

PILLARS = {
    "items": [
        {
            "title": "Platform Builder",
            "body": "Xyn compresses product bootstrapping into repeatable, modular components.",
        },
        {
            "title": "Composable Ops",
            "body": "Deployable reference stacks with observability and security baked in.",
        },
        {
            "title": "Velocity Metrics",
            "body": "Instrumented delivery pipelines aligned to business outcomes.",
        },
    ]
}

XYN_MD = textwrap.dedent(
    """
    # Xyn · Platform Builder

    Xyn is a configurable platform builder for teams that want to launch products quickly without sacrificing architecture. It combines blueprint-driven orchestration, reusable platform modules, and production-grade defaults so teams can ship with confidence — and evolve without rewrites.

    Xyn treats infrastructure and application components as peers in the same semantic universe: not “app + pile of tools,” but one coherent system with consistent naming, lifecycle, and governance.

    ## Why Xyn

    ### Production-grade foundations from day zero

    Start with secure, observable, scalable defaults — not “we’ll harden it later.” Xyn gives teams a baseline of production patterns that include:

    - identity & access boundaries
    - environment isolation
    - runtime policies and guardrails
    - auditability and traceability
    - cost + operational footprint visibility

    ### Composable services that keep velocity high

    Xyn is modular by design. Teams assemble platforms from reusable components:

    - Modules (capabilities like provisioning, networking, observability, messaging)
    - Bundles (curated sets of modules that work together)
    - Blueprints (declarative plans describing desired architecture + behavior)

    This creates speed that doesn’t degrade into chaos.

    ### Governance patterns for growing orgs

    Xyn doesn’t just create infrastructure — it creates an operating model. It supports:

    - standard registries of approved modules
    - consistent naming and versioning
    - promotion workflows (dev → stage → prod)
    - guardrails that don’t block autonomy

    ## Operating model for durable software

    Most teams can build a system. Fewer teams can build a system that stays buildable. Xyn is designed to keep systems coherent across:

    - feature growth
    - personnel changes
    - multi-team ownership
    - vendor swaps
    - scaling pressure

    ## Distilled from real builds

    Xyn is the distillation of build patterns used across regulated industries, SaaS platforms, and high-growth teams — where “move fast” must still mean secure, governable, observable, and explainable.
    """
).strip()

ABOUT_MD = textwrap.dedent(
    """
    ![Joshua Restivo](/josh-restivo.jpg)

    ## Joshua Restivo

    Joshua Restivo is the founder of Xyence, a platform consulting firm focused on AI-enabled operations, cloud control planes, and durable engineering systems. For more than 25 years, he has worked at the intersection of infrastructure, automation, and complex systems — helping organizations modernize environments, build AI-native platforms, and bring high-stakes products to market.

    He lives in downtown St. Louis inside the City Museum — not near it, not inspired by it, but inside it: a giant, climbable, welded, reclaimed architectural dreamscape where art is also structure and structure is also play. It’s an unusual place to call home, but it fits: Joshua has always been drawn to systems that are alive — layered, expressive, intricate, and unapologetically real.

    At night, when he drives back into the City from across the river, he watches the skyline gather itself into clarity — brighter, closer, inevitable. The feeling is part awe and part belonging. To him, cities are proof that complexity doesn’t have to be cold. They’re the most ambitious machines humans have ever built: networks of movement, logistics, story, resilience, failure, adaptation, and reinvention — all running at once.

    That worldview shows up in his work.

    Joshua has led platform initiatives across large environments like AT&T and Savvis/CenturyLink, and in startups spanning computer forensics, cloud orchestration, and advanced network engineering. Most recently, he architected Z1N — a Kubernetes-native, multi-tenant operations platform that unifies AI agents, orchestration engines, ERP-class workflows, and telecom automation across hybrid cloud systems. He has also built AIOps reasoning pipelines and enterprise API control planes designed to endure high transaction volume, operational chaos, and constant change.

    He’s known for translating complex technical systems into language that makes sense to business leaders, community stakeholders, and classrooms — and has delivered training to U.S. state and federal law enforcement agents and attorneys. His work has supported municipalities and charitable organizations through IT-focused volunteer initiatives, and is cited in Jose Baez’s New York Times best-selling book, *Presumed Guilty*.

    At the center of all of it is a single belief: the systems we build aren’t just technical — they’re cultural. They reveal what we value, what we tolerate, and what we’re willing to make durable. Joshua builds platforms the way he loves cities: layered, resilient, intelligently orchestrated — and capable of holding the full complexity of real life.

    ---

    **Highlights**
    - AI-enabled operations platforms, hybrid cloud control planes, autonomous remediation systems.
    - Scaled telecom operations from 65 to 1,200+ employees and guided teams through multiple successful exits.
    - Mentorship in WAN networking, information security, expert testimony, and full-stack engineering.
    """
).strip()


class Command(BaseCommand):
    help = "Seed Pages, MenuItems, and WebSections from the legacy xyn-api content."

    def handle(self, *args, **options):
        pages = {
            "home": {"title": "Home", "published": True},
            "about": {"title": "About", "published": True},
            "xyn": {"title": "Xyn", "published": True},
        }

        page_objs: dict[str, Page] = {}
        for slug, attrs in pages.items():
            page, _ = Page.objects.get_or_create(slug=slug, defaults=attrs)
            if page.title != attrs["title"] or page.published != attrs["published"]:
                page.title = attrs["title"]
                page.published = attrs["published"]
                page.save(update_fields=["title", "published", "updated_at"])
            page_objs[slug] = page

        menu_items = [
            {
                "label": "Home",
                "path": "/",
                "kind": MenuItem.Kind.PAGE,
                "page": page_objs["home"],
                "order": 10,
            },
            {
                "label": "About",
                "path": "/about",
                "kind": MenuItem.Kind.PAGE,
                "page": page_objs["about"],
                "order": 20,
            },
            {
                "label": "Xyn",
                "path": "/xyn",
                "kind": MenuItem.Kind.PAGE,
                "page": page_objs["xyn"],
                "order": 30,
            },
            {
                "label": "Articles",
                "path": "/articles",
                "kind": MenuItem.Kind.ARTICLES_INDEX,
                "page": None,
                "order": 40,
            },
        ]

        for item in menu_items:
            obj, _ = MenuItem.objects.get_or_create(path=item["path"], defaults=item)
            changed = False
            for key, value in item.items():
                if getattr(obj, key) != value:
                    setattr(obj, key, value)
                    changed = True
            if changed:
                obj.save()

        config = SiteConfig.objects.first()
        if not config:
            config = SiteConfig.objects.create(site_name="Xyence")
        elif config.site_name != "Xyence":
            config.site_name = "Xyence"
            config.save(update_fields=["site_name", "updated_at"])

        self._upsert_section(
            page_objs["home"],
            key="home-hero",
            section_type=WebSection.SectionType.HERO,
            title="",
            body_md="",
            data_json=HOME_HERO,
            order=10,
        )
        self._upsert_section(
            page_objs["home"],
            key="home-services",
            section_type=WebSection.SectionType.SERVICE_CARDS,
            title="Services",
            body_md="",
            data_json=SERVICES,
            order=20,
        )
        self._upsert_section(
            page_objs["home"],
            key="home-pillars",
            section_type=WebSection.SectionType.FEATURE_GRID,
            title="Platform Builder Pillars",
            body_md="",
            data_json=PILLARS,
            order=30,
        )
        self._upsert_section(
            page_objs["home"],
            key="home-xyn",
            section_type=WebSection.SectionType.SIMPLE_MD,
            title="",
            body_md=XYN_MD,
            data_json=None,
            order=40,
        )
        self._upsert_section(
            page_objs["home"],
            key="home-cta",
            section_type=WebSection.SectionType.CTA_BAND,
            title="",
            body_md="",
            data_json={
                "headline": "Read the field notes",
                "body": "The Xyn manifesto kicks off the series. More technical deep dives are publishing soon.",
                "cta": {"label": "Go to articles", "href": "/articles"},
            },
            order=50,
        )
        self._upsert_section(
            page_objs["about"],
            key="about-bio",
            section_type=WebSection.SectionType.SIMPLE_MD,
            title="About Xyence",
            body_md=ABOUT_MD,
            data_json=None,
            order=10,
        )

        self._upsert_section(
            page_objs["xyn"],
            key="xyn-overview",
            section_type=WebSection.SectionType.SIMPLE_MD,
            title="",
            body_md=XYN_MD,
            data_json=None,
            order=10,
        )

        self.stdout.write(self.style.SUCCESS("Seeded public site content."))

    def _upsert_section(
        self,
        page: Page,
        key: str,
        section_type: str,
        title: str,
        body_md: str,
        data_json: Any,
        order: int,
    ) -> None:
        section, _ = WebSection.objects.get_or_create(page=page, key=key)
        section.section_type = section_type
        section.title = title
        section.body_md = body_md
        section.data_json = data_json
        section.order = order
        section.visible = True
        section.save()
