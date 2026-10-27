"""
TrustGuard AI — Application Entry Point
Starts the local development server.
"""

from app import app
from config import Config

if __name__ == "__main__":
    print("=" * 60)
    print(" TrustGuard AI — Digital Trust & Scam Detection Platform")
    print(f" Starting local server on http://127.0.0.1:5000 (Debug: {Config.DEBUG})")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
