from rest_framework import serializers

from .models import Article, ArticleVersion


class ArticleVersionSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = ArticleVersion
        fields = ["version_number", "created_at", "source"]


class ArticleSerializer(serializers.ModelSerializer):
    version_count = serializers.SerializerMethodField()
    latest_version_number = serializers.SerializerMethodField()
    versions = ArticleVersionSummarySerializer(many=True, read_only=True)

    class Meta:
        model = Article
        fields = [
            "id",
            "title",
            "slug",
            "summary",
            "body",
            "status",
            "published_at",
            "created_at",
            "updated_at",
            "version_count",
            "latest_version_number",
            "versions",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_version_count(self, obj):
        return obj.versions.count()

    def get_latest_version_number(self, obj):
        latest = obj.versions.order_by("-version_number").first()
        return latest.version_number if latest else None
