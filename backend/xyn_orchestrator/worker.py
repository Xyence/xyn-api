import os

import redis
from rq import Worker


def main() -> None:
    redis_url = os.environ.get("XYENCE_JOBS_REDIS_URL", "redis://redis:6379/0")
    conn = redis.Redis.from_url(redis_url)
    worker = Worker(["default"], connection=conn)
    worker.work()


if __name__ == "__main__":
    main()
