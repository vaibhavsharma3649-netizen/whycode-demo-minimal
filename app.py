"""
Minimal Web Application Entrypoint
"""
from auth import TaggedJSONSerializer

class Application:
    def __init__(self, secret: str = "secret-production-key"):
        self.auth = TaggedJSONSerializer(secret)

    def handle_request(self, token: str, signature: str) -> dict:
        if self.auth.verify_token(token, signature):
            return {"status": "authenticated", "code": 200}
        return {"status": "unauthorized", "code": 401}

if __name__ == "__main__":
    app = Application()
    print("Application initialized successfully.")
