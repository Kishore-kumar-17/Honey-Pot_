class ResponseGenerator:
    @staticmethod
    def login_failure():
        return {"status": "error", "message": "Invalid credentials", "code": 401}

    @staticmethod
    def login_success_fake():
        # Deceptive success to keep the attacker engaged
        return {
            "status": "success",
            "message": "Login successful",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake_token",
            "user": {"id": 1, "username": "admin", "role": "superuser"}
        }

    @staticmethod
    def scan_response(path: str):
        if ".env" in path:
            return "DB_PASSWORD=admin\nDB_USER=root\nSECRET_KEY=12345"
        return {"status": "not_found", "message": f"Resource {path} not found"}
