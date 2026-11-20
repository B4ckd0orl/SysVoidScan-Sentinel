import os
import shutil


class Wordlists:
    COMMON_DIRS = [
        "admin", "backup", "cgi-bin", "css", "js", "images", "uploads", "download",
        "include", "inc", "config", "api", "v1", "old", "test", "dev", "hidden",
        "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.backup",
        "phpinfo.php", "info.php", "backup.zip", "backup.sql", "dump.sql",
        "wp-admin", "wp-content", "administrator", "phpmyadmin", "adminer.php",
        ".htaccess", ".htpasswd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
        ".well-known/security.txt", "package.json", "composer.json", "server-status",
    ]

    SECLISTS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
    SECLISTS_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
    SECLISTS_PASSWORDS = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
    SECLISTS_DNS = "/usr/share/seclists/Discovery/DNS/namelist.txt"
    SECLISTS_USERS = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
    SECLISTS_USERS_SHORT = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    ROCKYOU_PATH = "/usr/share/wordlists/rockyou.txt"
    ROCKYOU_GZ = "/usr/share/wordlists/rockyou.txt.gz"

    DEFAULT_PASSWORDS = [
        "123456", "password", "123456789", "12345", "12345678", "qwerty",
        "abc123", "admin", "letmein", "welcome",
    ]

    API_ENDPOINTS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3", "/rest", "/rest/v1",
        "/api/users", "/api/user", "/api/accounts", "/api/account",
        "/api/admin", "/api/me", "/api/profile", "/api/whoami",
        "/api/config", "/api/settings", "/api/flags", "/api/data",
        "/api/keys", "/api/tokens", "/api/secrets", "/api/credentials",
        "/api/debug", "/api/test", "/api/internal",
        "/rest/users", "/rest/user", "/rest/admin", "/rest/profile",
        "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/redoc", "/docs", "/api/docs", "/api/swagger",
        "/graphql", "/graphiql", "/api/graphql", "/query", "/api/query",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/actuator/beans", "/actuator/httptrace", "/actuator/loggers",
        "/health", "/metrics", "/info", "/status", "/ping",
        "/api/auth", "/api/login", "/api/token", "/api/refresh",
        "/api/register", "/api/signup",
        "/.well-known/", "/api/version", "/api/changelog",
        "/console", "/api/console", "/h2-console",
    ]

    API_BASE_PREFIXES = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/services", "/services/api",
    ]

    API_RESOURCES = [
        "users", "user", "accounts", "account", "me", "profile", "whoami",
        "auth", "login", "logout", "register", "signup", "signin",
        "token", "tokens", "refresh", "session", "sessions",
        "password", "reset-password", "forgot-password", "2fa", "mfa", "otp",
        "admin", "config", "settings", "flags", "feature-flags",
        "permissions", "roles", "groups", "privileges",
        "audit", "audit-log", "logs", "events",
        "data", "items", "products", "orders", "invoices", "payments",
        "transactions", "transfer", "transfers", "wallets", "balance",
        "subscriptions", "plans", "billing", "cart", "checkout",
        "notes", "messages", "chats", "comments", "posts", "articles",
        "files", "uploads", "documents", "attachments", "media", "images",
        "search", "filter", "query", "tags", "categories",
        "stats", "metrics", "health", "status", "version", "info",
        "debug", "test", "internal", "private", "hidden",
        "keys", "secrets", "credentials", "api-keys",
        "export", "import", "backup", "dump", "report", "reports",
        "notifications", "webhooks", "callbacks", "subscribe",
        "feed", "feeds", "activity", "history",
    ]

    MASS_ASSIGNMENT_FIELDS = [
        {"is_admin": True},
        {"role": "admin"},
        {"admin": True},
        {"isAdmin": True},
        {"privilege": "admin"},
        {"user_role": "administrator"},
        {"account_type": "premium"},
        {"verified": True},
        {"status": "active"},
        {"credits": 9999},
        {"balance": 9999},
        {"permissions": ["admin", "superuser"]},
    ]

    LOGIN_PATHS = [
        "/login", "/signin", "/auth", "/logon", "/login.php", "/login.html",
        "/user/login", "/account/login", "/admin/login", "/wp-login.php",
    ]

    DEFAULT_WORDLIST_DIR = "/usr/share/wordlists"
    # Wordlists instaladas localmente en Windows (SecLists descargado)
    LOCAL_WORDLIST_DIR = r"C:\pentest-tools\wordlists"

    def find_wordlist(self, name):
        candidates = [
            os.path.join(self.DEFAULT_WORDLIST_DIR, name),
            os.path.join("/usr/share/seclists", name),
            os.path.join("/opt", name),
            os.path.expanduser(f"~/{name}"),
            os.path.join(self.LOCAL_WORDLIST_DIR, os.path.basename(name)),
            name,
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        if shutil.which(name):
            return name
        return None

    def get_password_wordlist(self):
        for path in (self.SECLISTS_PASSWORDS, self.ROCKYOU_PATH, self.ROCKYOU_GZ,
                     os.path.join(self.LOCAL_WORDLIST_DIR,
                                  "xato-net-10-million-passwords-10000.txt"),
                     os.path.join(self.LOCAL_WORDLIST_DIR, "namelist.txt")):
            if os.path.isfile(path):
                return path
        return None
