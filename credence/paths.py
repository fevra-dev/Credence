"""
Sensitive paths database.

Each path has:
- path: The URL path to check
- category: Category for grouping
- severity: Severity if found exposed
- description: Human-readable description
- signatures: Response body strings that confirm exposure
- content_types: Valid content-types for this file type
"""

from typing import List

from .models import Category, PathDefinition, Severity

# ============================================================
# SENSITIVE PATHS DATABASE
# ============================================================

SENSITIVE_PATHS: List[PathDefinition] = [
    # --------------------------------------------------------
    # GIT REPOSITORY FILES
    # --------------------------------------------------------
    PathDefinition(
        path=".git/config",
        category=Category.GIT,
        severity=Severity.CRITICAL,
        description="Git repository configuration exposed",
        signatures=["[core]", "[remote", "repositoryformatversion", "[branch"],
        content_types=["text/plain", "application/octet-stream"],
    ),
    PathDefinition(
        path=".git/HEAD",
        category=Category.GIT,
        severity=Severity.CRITICAL,
        description="Git HEAD reference exposed",
        signatures=["ref: refs/heads/", "ref: refs/", "refs/heads/main", "refs/heads/master"],
        content_types=["text/plain", "application/octet-stream"],
    ),
    PathDefinition(
        path=".git/index",
        category=Category.GIT,
        severity=Severity.CRITICAL,
        description="Git index file exposed (contains file listing)",
        signatures=["DIRC"],  # Git index magic bytes
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path=".git/logs/HEAD",
        category=Category.GIT,
        severity=Severity.CRITICAL,
        description="Git commit logs exposed",
        signatures=["commit:", "0000000000000000000000000000000000000000"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".git/COMMIT_EDITMSG",
        category=Category.GIT,
        severity=Severity.HIGH,
        description="Git last commit message exposed",
        signatures=[],  # Any non-empty response
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".git/description",
        category=Category.GIT,
        severity=Severity.MEDIUM,
        description="Git repository description exposed",
        signatures=["Unnamed repository"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".git/packed-refs",
        category=Category.GIT,
        severity=Severity.HIGH,
        description="Git packed references exposed",
        signatures=["# pack-refs", "refs/heads/", "refs/tags/"],
        content_types=["text/plain"],
    ),
    # --------------------------------------------------------
    # ENVIRONMENT FILES
    # --------------------------------------------------------
    PathDefinition(
        path=".env",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Environment file with credentials exposed",
        signatures=[
            "DB_PASSWORD",
            "DATABASE_URL",
            "API_KEY",
            "SECRET_KEY",
            "AWS_ACCESS",
            "AWS_SECRET",
            "STRIPE_",
            "SENDGRID",
            "MYSQL_",
            "POSTGRES_",
            "REDIS_",
            "MONGO",
            "JWT_SECRET",
            "APP_KEY",
            "ENCRYPTION_KEY",
        ],
        content_types=["text/plain", "application/octet-stream"],
    ),
    PathDefinition(
        path=".env.local",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Local environment file exposed",
        signatures=["DB_", "API_", "SECRET", "PASSWORD", "KEY="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.production",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Production environment file exposed",
        signatures=["DB_", "API_", "SECRET", "PASSWORD", "KEY="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.development",
        category=Category.ENV,
        severity=Severity.HIGH,
        description="Development environment file exposed",
        signatures=["DB_", "API_", "SECRET", "PASSWORD", "KEY="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.backup",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Environment backup file exposed",
        signatures=["DB_", "API_", "SECRET", "PASSWORD", "KEY="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.example",
        category=Category.ENV,
        severity=Severity.LOW,
        description="Environment example file (may contain real values)",
        signatures=["DB_", "API_", "SECRET", "KEY="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.sample",
        category=Category.ENV,
        severity=Severity.LOW,
        description="Environment sample file (may contain real values)",
        signatures=["DB_", "API_", "SECRET", "KEY="],
        content_types=["text/plain"],
    ),
    # --------------------------------------------------------
    # CONFIGURATION FILES
    # --------------------------------------------------------
    PathDefinition(
        path="wp-config.php",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="WordPress configuration with database credentials",
        signatures=[
            "DB_NAME",
            "DB_USER",
            "DB_PASSWORD",
            "DB_HOST",
            "define(",
            "table_prefix",
            "WP_DEBUG",
            "AUTH_KEY",
        ],
        content_types=["text/plain", "text/html", "application/x-httpd-php"],
    ),
    PathDefinition(
        path="wp-config.php.bak",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="WordPress configuration backup",
        signatures=["DB_NAME", "DB_USER", "DB_PASSWORD", "define("],
        content_types=["text/plain", "application/octet-stream"],
    ),
    PathDefinition(
        path="wp-config.php.old",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Old WordPress configuration",
        signatures=["DB_NAME", "DB_USER", "DB_PASSWORD", "define("],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="wp-config.php.save",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Saved WordPress configuration",
        signatures=["DB_NAME", "DB_USER", "DB_PASSWORD", "define("],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="wp-config.php.swp",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="WordPress config vim swap file",
        signatures=[],  # Binary file
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path="wp-config.php~",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="WordPress configuration backup (tilde)",
        signatures=["DB_NAME", "DB_USER", "DB_PASSWORD", "define("],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="config.php",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="PHP configuration file exposed",
        signatures=["<?php", "password", "database", "mysql", "pgsql"],
        content_types=["text/plain", "text/html"],
    ),
    PathDefinition(
        path="config.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="YAML configuration file exposed",
        signatures=["password:", "secret:", "database:", "api_key:"],
        content_types=["text/plain", "text/yaml", "application/x-yaml"],
    ),
    PathDefinition(
        path="config.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="YAML configuration file exposed",
        signatures=["password:", "secret:", "database:", "api_key:"],
        content_types=["text/plain", "text/yaml", "application/x-yaml"],
    ),
    PathDefinition(
        path="config.json",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="JSON configuration file exposed",
        signatures=['"password"', '"secret"', '"apiKey"', '"database"'],
        content_types=["application/json", "text/plain"],
    ),
    PathDefinition(
        path="settings.py",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Django settings file exposed",
        signatures=["SECRET_KEY", "DATABASES", "DEBUG", "ALLOWED_HOSTS"],
        content_types=["text/plain", "text/x-python"],
    ),
    PathDefinition(
        path="application.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Spring Boot configuration exposed",
        signatures=["spring:", "datasource:", "password:", "username:"],
        content_types=["text/plain", "text/yaml"],
    ),
    PathDefinition(
        path="application.properties",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Java application properties exposed",
        signatures=["spring.", "jdbc.", "password=", "secret="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="database.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Rails database configuration exposed",
        signatures=["adapter:", "database:", "username:", "password:"],
        content_types=["text/plain", "text/yaml"],
    ),
    PathDefinition(
        path="secrets.yml",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Rails secrets file exposed",
        signatures=["secret_key_base:", "production:", "development:"],
        content_types=["text/plain", "text/yaml"],
    ),
    PathDefinition(
        path="credentials.yml.enc",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Rails encrypted credentials (may be decryptable)",
        signatures=[],
        content_types=["application/octet-stream"],
    ),
    # --------------------------------------------------------
    # BACKUP FILES
    # --------------------------------------------------------
    PathDefinition(
        path="backup.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="SQL database backup exposed",
        signatures=["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump", "pg_dump"],
        content_types=["text/plain", "application/sql", "application/octet-stream"],
    ),
    PathDefinition(
        path="backup.zip",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Backup archive exposed",
        signatures=["PK"],  # ZIP magic bytes
        content_types=["application/zip", "application/octet-stream"],
    ),
    PathDefinition(
        path="backup.tar.gz",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Compressed backup archive exposed",
        signatures=[],
        content_types=["application/gzip", "application/x-gzip", "application/octet-stream"],
    ),
    PathDefinition(
        path="dump.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Database dump exposed",
        signatures=["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    PathDefinition(
        path="database.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Database SQL file exposed",
        signatures=["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    PathDefinition(
        path="db.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Database SQL file exposed",
        signatures=["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    PathDefinition(
        path="data.sql",
        category=Category.BACKUP,
        severity=Severity.HIGH,
        description="SQL data file exposed",
        signatures=["INSERT INTO", "CREATE TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    PathDefinition(
        path="backup.tar",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Tar backup archive exposed",
        signatures=[],
        content_types=["application/x-tar", "application/octet-stream"],
    ),
    PathDefinition(
        path="site.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Site database backup exposed",
        signatures=["INSERT INTO", "CREATE TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    # --------------------------------------------------------
    # OTHER VERSION CONTROL
    # --------------------------------------------------------
    PathDefinition(
        path=".svn/entries",
        category=Category.VCS,
        severity=Severity.HIGH,
        description="SVN repository entries exposed",
        signatures=["dir", "file", "svn:"],
        content_types=["text/plain", "application/xml"],
    ),
    PathDefinition(
        path=".svn/wc.db",
        category=Category.VCS,
        severity=Severity.CRITICAL,
        description="SVN working copy database exposed",
        signatures=["SQLite"],
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path=".hg/store/00manifest.i",
        category=Category.VCS,
        severity=Severity.CRITICAL,
        description="Mercurial repository manifest exposed",
        signatures=[],
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path=".bzr/README",
        category=Category.VCS,
        severity=Severity.HIGH,
        description="Bazaar repository exposed",
        signatures=["Bazaar", "bzr"],
        content_types=["text/plain"],
    ),
    # --------------------------------------------------------
    # DEBUG / INFORMATION DISCLOSURE
    # --------------------------------------------------------
    PathDefinition(
        path="phpinfo.php",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="PHP information disclosure",
        signatures=["PHP Version", "phpinfo()", "PHP Credits", "Configuration"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="info.php",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="PHP information disclosure",
        signatures=["PHP Version", "phpinfo()", "Configuration"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="test.php",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="Test PHP file (may contain debug info)",
        signatures=["<?php", "test"],
        content_types=["text/html", "text/plain"],
    ),
    PathDefinition(
        path="debug.log",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Debug log file exposed",
        signatures=["error", "warning", "debug", "exception", "stack trace"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="error.log",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Error log file exposed",
        signatures=["error", "warning", "fatal", "exception"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="server-status",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Apache server status exposed",
        signatures=["Apache Server Status", "Server Version", "Current Time"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="server-info",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Apache server info exposed",
        signatures=["Apache Server Information", "Server Settings"],
        content_types=["text/html"],
    ),
    # --------------------------------------------------------
    # OTHER SENSITIVE FILES
    # --------------------------------------------------------
    PathDefinition(
        path=".htpasswd",
        category=Category.SENSITIVE,
        severity=Severity.HIGH,
        description="Apache password file exposed",
        signatures=[":$apr1$", ":{SHA}", ":$2y$", ":$2a$"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".htaccess",
        category=Category.SENSITIVE,
        severity=Severity.MEDIUM,
        description="Apache configuration exposed",
        signatures=["RewriteEngine", "RewriteRule", "AuthType", "Require"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".DS_Store",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="macOS directory metadata exposed",
        signatures=["Bud1"],  # DS_Store magic bytes
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path="Thumbs.db",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Windows thumbnail cache exposed",
        signatures=[],
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path="crossdomain.xml",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Flash cross-domain policy (may be permissive)",
        signatures=["cross-domain-policy", "allow-access-from"],
        content_types=["text/xml", "application/xml"],
    ),
    PathDefinition(
        path="clientaccesspolicy.xml",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Silverlight cross-domain policy",
        signatures=["access-policy", "cross-domain-access"],
        content_types=["text/xml", "application/xml"],
    ),
    PathDefinition(
        path=".idea/workspace.xml",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="IntelliJ IDEA workspace configuration",
        signatures=["<?xml", "project"],
        content_types=["text/xml", "application/xml"],
    ),
    PathDefinition(
        path=".vscode/settings.json",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="VS Code settings (may contain sensitive paths)",
        signatures=["{", "settings"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="composer.json",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="PHP Composer dependencies (information disclosure)",
        signatures=["require", "autoload", "name"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="package.json",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Node.js package configuration",
        signatures=["dependencies", "devDependencies", "scripts"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="Gemfile",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Ruby Gemfile (information disclosure)",
        signatures=["source", "gem "],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="requirements.txt",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Python requirements (information disclosure)",
        signatures=["==", ">=", "django", "flask", "requests"],
        content_types=["text/plain"],
    ),
    # --------------------------------------------------------
    # API DOCUMENTATION (often exposes internal endpoints)
    # --------------------------------------------------------
    PathDefinition(
        path="swagger.json",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Swagger/OpenAPI specification exposed",
        signatures=["swagger", "openapi", "paths", "definitions"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="swagger.yaml",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Swagger/OpenAPI specification exposed",
        signatures=["swagger:", "openapi:", "paths:"],
        content_types=["text/yaml", "text/plain"],
    ),
    PathDefinition(
        path="openapi.json",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="OpenAPI specification exposed",
        signatures=["openapi", "paths", "components"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="api-docs",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="API documentation endpoint",
        signatures=["api", "swagger", "endpoint"],
        content_types=["text/html", "application/json"],
    ),
    PathDefinition(
        path="graphql",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="GraphQL endpoint (check for introspection)",
        signatures=["graphql", "query", "mutation"],
        content_types=["text/html", "application/json"],
    ),
]


def get_all_paths() -> List[PathDefinition]:
    """Return all sensitive paths."""
    return SENSITIVE_PATHS


def get_paths_by_category(category: Category) -> List[PathDefinition]:
    """Return paths filtered by category."""
    return [p for p in SENSITIVE_PATHS if p.category == category]


def get_high_priority_paths() -> List[PathDefinition]:
    """Return only CRITICAL and HIGH severity paths for quick scans."""
    return [
        p for p in SENSITIVE_PATHS if p.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

