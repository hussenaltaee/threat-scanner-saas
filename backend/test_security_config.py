import os
from pathlib import Path


def test_db_path_is_absolute():
    from db import get_db_path

    db_path = get_db_path()
    assert isinstance(db_path, Path)
    assert db_path.is_absolute()
    assert db_path.name == "database.db"


def test_wpscan_token_comes_from_environment():
    import analyzer

    token = analyzer.get_wpscan_api_token()
    assert token == os.getenv("WPSCAN_API_TOKEN", "").strip()


def test_auth_secret_is_not_hardcoded():
    from auth import get_secret

    secret = get_secret()
    assert secret != "SUPER_SECRET_KEY_123456789"


def test_render_and_localhost_origins_are_allowed_for_cors():
    import main

    middleware_kwargs = {}
    for middleware in main.app.user_middleware:
        if middleware.cls.__name__ == "CORSMiddleware":
            middleware_kwargs = middleware.kwargs
            break

    assert middleware_kwargs.get("allow_credentials") is True
    assert "https://threat-frontend.onrender.com" in middleware_kwargs.get("allow_origins", [])
    assert middleware_kwargs.get("allow_origin_regex") is not None
