import base64
from typing import Iterable, List

import requests
from allauth.socialaccount.models import SocialToken
from django.utils import timezone

from .models import GitHubConfig, GitHubOrganization, GitHubRepo, GitHubRepoChunk
from django.contrib.postgres.search import SearchVector

GITHUB_API = "https://api.github.com"


def _get_access_token(config: GitHubConfig) -> str:
    if config.access_token:
        return config.access_token
    if config.social_account_id:
        token = (
            SocialToken.objects.filter(account_id=config.social_account_id)
            .order_by("-id")
            .first()
        )
        if token:
            return token.token
    raise ValueError("No GitHub access token available. Add a PAT or connect via OAuth.")


def _headers(config: GitHubConfig) -> dict:
    return {
        "Authorization": f"Bearer {_get_access_token(config)}",
        "Accept": "application/vnd.github+json",
    }


def list_user_orgs(config: GitHubConfig) -> List[dict]:
    orgs = []
    page = 1
    while True:
        resp = requests.get(
            f"{GITHUB_API}/user/orgs",
            headers=_headers(config),
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        resp.raise_for_status()
        chunk = resp.json()
        if not chunk:
            break
        orgs.extend(chunk)
        page += 1
    return orgs


def sync_orgs(config: GitHubConfig) -> List[GitHubOrganization]:
    orgs = []
    for org in list_user_orgs(config):
        obj, _created = GitHubOrganization.objects.update_or_create(
            config=config,
            login=org["login"],
            defaults={
                "name": org.get("name") or "",
                "description": org.get("description") or "",
            },
        )
        orgs.append(obj)
    return orgs


def list_org_repos(config: GitHubConfig) -> List[dict]:
    repos = []
    page = 1
    org_login = config.organization_login()
    if not org_login:
        raise ValueError("Organization is not set. Import orgs and select one in GitHub Config.")
    while True:
        resp = requests.get(
            f"{GITHUB_API}/orgs/{org_login}/repos",
            headers=_headers(config),
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        resp.raise_for_status()
        chunk = resp.json()
        if not chunk:
            break
        repos.extend(chunk)
        page += 1
    return repos


def sync_repos(config: GitHubConfig) -> List[GitHubRepo]:
    repos = []
    for repo in list_org_repos(config):
        obj, _created = GitHubRepo.objects.update_or_create(
            full_name=repo["full_name"],
            defaults={
                "config": config,
                "name": repo["name"],
                "default_branch": repo.get("default_branch", ""),
                "description": repo.get("description") or "",
            },
        )
        repos.append(obj)
    return repos


def _fetch_repo_tree(config: GitHubConfig, repo: GitHubRepo) -> List[dict]:
    branch = repo.default_branch or "main"
    resp = requests.get(
        f"{GITHUB_API}/repos/{repo.full_name}/git/trees/{branch}",
        headers=_headers(config),
        params={"recursive": 1},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("tree", [])


def _fetch_blob(config: GitHubConfig, repo: GitHubRepo, sha: str) -> str:
    resp = requests.get(
        f"{GITHUB_API}/repos/{repo.full_name}/git/blobs/{sha}",
        headers=_headers(config),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
    return data.get("content", "")


def _chunk_text(text: str, max_len: int = 1200, overlap: int = 200) -> Iterable[str]:
    start = 0
    length = len(text)
    while start < length:
        end = min(start + max_len, length)
        yield text[start:end]
        if end == length:
            break
        start = max(end - overlap, 0)


def index_repo(repo: GitHubRepo) -> int:
    config = repo.config
    tree = _fetch_repo_tree(config, repo)
    md_blobs = [item for item in tree if item.get("type") == "blob" and item.get("path", "").lower().endswith(".md")]

    GitHubRepoChunk.objects.filter(repo=repo).delete()

    created = 0
    for blob in md_blobs:
        content = _fetch_blob(config, repo, blob["sha"])
        for chunk in _chunk_text(content):
            GitHubRepoChunk.objects.create(
                repo=repo,
                path=blob.get("path", ""),
                content=chunk,
            )
            created += 1

    GitHubRepoChunk.objects.filter(repo=repo).update(content_search=SearchVector("content"))
    repo.last_indexed_at = timezone.now()
    repo.save(update_fields=["last_indexed_at"])
    return created
