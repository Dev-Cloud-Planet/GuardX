"""
GuardX Public REST API
API key authenticated endpoints for CI/CD and SIEM integration.

Usage:
    from guardx.api import api_bp
    app.register_blueprint(api_bp)
"""

from .routes import api_bp

__all__ = ["api_bp"]
