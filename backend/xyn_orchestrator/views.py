from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Article, ArticleVersion
from .serializers import ArticleSerializer


class ArticleViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ArticleSerializer
    permission_classes = [AllowAny]
    lookup_field = "slug"

    def get_queryset(self):
        return Article.objects.filter(status="published")

    def retrieve(self, request, *args, **kwargs):
        article = self.get_object()
        serializer = self.get_serializer(article)
        data = serializer.data
        version_param = request.query_params.get("version")
        if version_param:
            try:
                version_number = int(version_param)
            except ValueError:
                version_number = None
            if version_number:
                try:
                    version = ArticleVersion.objects.get(article=article, version_number=version_number)
                except ArticleVersion.DoesNotExist:
                    return Response({"detail": "Version not found."}, status=404)
                data["title"] = version.title
                data["summary"] = version.summary
                data["body"] = version.body
                data["version_number"] = version.version_number
                data["version_created_at"] = version.created_at
        return Response(data)
