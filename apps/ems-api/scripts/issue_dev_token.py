import argparse
import os
import time

import jwt


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a dev JWT for EMS.")
    parser.add_argument("--role", choices=["admin", "viewer"], default="admin")
    args = parser.parse_args()
    secret = os.environ.get("EMS_JWT_SECRET", "").strip()
    if not secret:
        raise SystemExit("EMS_JWT_SECRET is required")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "sub": f"dev-{args.role}",
        "email": f"{args.role}@example.com",
        "roles": [args.role],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    print(token)


if __name__ == "__main__":
    main()
