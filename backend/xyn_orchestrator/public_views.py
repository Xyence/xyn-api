from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from .models import Article


@require_GET
def public_articles(request):
    queryset = Article.objects.filter(status="published").order_by("-published_at", "-created_at")
    page_size = int(request.GET.get("page_size", 10))
    page_number = int(request.GET.get("page", 1))
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(page_number)

    items = []
    for article in page.object_list:
        items.append(
            {
                "title": article.title,
                "slug": article.slug,
                "summary": article.summary,
                "published_at": article.published_at,
                "updated_at": article.updated_at,
            }
        )

    payload = {
        "items": items,
        "count": paginator.count,
        "next": page.next_page_number() if page.has_next() else None,
        "prev": page.previous_page_number() if page.has_previous() else None,
    }
    return JsonResponse(payload)


@require_GET
def public_article_detail(_request, slug: str):
    article = get_object_or_404(Article, slug=slug, status="published")
    payload = {
        "title": article.title,
        "slug": article.slug,
        "summary": article.summary,
        "published_at": article.published_at,
        "updated_at": article.updated_at,
        "body_html": article.body,
        "excerpt": article.summary,
    }
    return JsonResponse(payload)
