"""
Extended Sensitive Paths Database.

Adds 100+ new detection signatures covering:
- Modern JavaScript frameworks (Next.js, Nuxt, Remix, SvelteKit)
- Cloud configuration files
- Container and orchestration files
- API documentation
- Debug and monitoring endpoints
- Package manager files
- IDE and editor configurations
- Cloud provider specific files

Import this alongside the main paths.py to extend detection coverage.
"""

from typing import List

from .models import Category, PathDefinition, Severity

# ============================================================
# EXTENDED SENSITIVE PATHS DATABASE
# ============================================================

EXTENDED_PATHS: List[PathDefinition] = [
    # --------------------------------------------------------
    # MODERN JAVASCRIPT FRAMEWORKS
    # --------------------------------------------------------

    # Next.js
    PathDefinition(
        path="_next/static/chunks/webpack.js",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Next.js webpack bundle exposed (may contain source maps)",
        signatures=["webpackChunk", "__webpack_require__"],
        content_types=["application/javascript", "text/javascript"],
    ),
    PathDefinition(
        path="_next/static/development/_buildManifest.js",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="Next.js build manifest (reveals routes)",
        signatures=["self.__BUILD_MANIFEST", "sortedPages"],
        content_types=["application/javascript"],
    ),
    PathDefinition(
        path="next.config.js",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Next.js configuration file exposed",
        signatures=["module.exports", "nextConfig", "webpack"],
        content_types=["application/javascript", "text/plain"],
    ),
    PathDefinition(
        path=".next/server/pages-manifest.json",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Next.js pages manifest exposed",
        signatures=["/_app", "/_document", "pages"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path=".next/BUILD_ID",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="Next.js build ID exposed",
        signatures=[],
        content_types=["text/plain"],
    ),

    # Nuxt.js
    PathDefinition(
        path=".nuxt/dist/server/server.js",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="Nuxt.js server bundle exposed",
        signatures=["nuxt", "__webpack_require__", "module.exports"],
        content_types=["application/javascript"],
    ),
    PathDefinition(
        path="nuxt.config.js",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Nuxt.js configuration exposed",
        signatures=["export default", "nuxtConfig", "modules"],
        content_types=["application/javascript", "text/plain"],
    ),
    PathDefinition(
        path="nuxt.config.ts",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Nuxt.js TypeScript configuration exposed",
        signatures=["defineNuxtConfig", "export default"],
        content_types=["text/plain", "application/typescript"],
    ),

    # Vite
    PathDefinition(
        path="vite.config.js",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Vite configuration exposed",
        signatures=["defineConfig", "vite", "plugins"],
        content_types=["application/javascript", "text/plain"],
    ),
    PathDefinition(
        path="vite.config.ts",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Vite TypeScript configuration exposed",
        signatures=["defineConfig", "vite", "plugins"],
        content_types=["text/plain"],
    ),

    # Remix
    PathDefinition(
        path="remix.config.js",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Remix configuration exposed",
        signatures=["module.exports", "appDirectory", "serverBuildPath"],
        content_types=["application/javascript", "text/plain"],
    ),

    # SvelteKit
    PathDefinition(
        path="svelte.config.js",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="SvelteKit configuration exposed",
        signatures=["adapter", "kit", "preprocess"],
        content_types=["application/javascript", "text/plain"],
    ),

    # --------------------------------------------------------
    # SOURCE MAPS (Critical for source code exposure)
    # --------------------------------------------------------
    PathDefinition(
        path="main.js.map",
        category=Category.DEBUG,
        severity=Severity.CRITICAL,
        description="JavaScript source map exposed - full source code available",
        signatures=['"version":', '"sources":', '"sourcesContent":'],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="bundle.js.map",
        category=Category.DEBUG,
        severity=Severity.CRITICAL,
        description="Bundle source map exposed",
        signatures=['"version":', '"sources":', '"mappings":'],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="app.js.map",
        category=Category.DEBUG,
        severity=Severity.CRITICAL,
        description="Application source map exposed",
        signatures=['"version":', '"sources":', '"sourcesContent":'],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="vendor.js.map",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="Vendor source map exposed",
        signatures=['"version":', '"sources":', '"mappings":'],
        content_types=["application/json"],
    ),

    # --------------------------------------------------------
    # CLOUD CONFIGURATION FILES
    # --------------------------------------------------------

    # AWS
    PathDefinition(
        path=".aws/credentials",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="AWS credentials file exposed",
        signatures=["aws_access_key_id", "aws_secret_access_key"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".aws/config",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="AWS configuration file exposed",
        signatures=["[default]", "region", "output"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="aws-exports.js",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="AWS Amplify exports exposed",
        signatures=["aws_project_region", "aws_cognito", "aws_appsync"],
        content_types=["application/javascript"],
    ),
    PathDefinition(
        path="amplify/backend/amplify-meta.json",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="AWS Amplify backend metadata exposed",
        signatures=["providers", "awscloudformation", "api"],
        content_types=["application/json"],
    ),

    # Google Cloud
    PathDefinition(
        path="google-credentials.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Google Cloud service account credentials exposed",
        signatures=["type", "private_key", "client_email"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="service-account.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Service account credentials exposed",
        signatures=["private_key", "client_email", "project_id"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="firebase-adminsdk.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Firebase Admin SDK credentials exposed",
        signatures=["type", "private_key", "firebase"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="firebase.json",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Firebase configuration exposed",
        signatures=["hosting", "functions", "firestore"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path=".firebaserc",
        category=Category.CONFIG,
        severity=Severity.LOW,
        description="Firebase project configuration exposed",
        signatures=["projects", "default"],
        content_types=["application/json"],
    ),

    # Azure
    PathDefinition(
        path="azure-pipelines.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Azure DevOps pipeline configuration exposed",
        signatures=["trigger", "pool", "stages", "jobs"],
        content_types=["text/yaml", "text/plain"],
    ),
    PathDefinition(
        path="azuredeploy.json",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Azure ARM template exposed",
        signatures=["$schema", "resources", "parameters"],
        content_types=["application/json"],
    ),

    # --------------------------------------------------------
    # CONTAINER & ORCHESTRATION
    # --------------------------------------------------------
    PathDefinition(
        path="kubernetes.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Kubernetes manifest exposed",
        signatures=["apiVersion", "kind", "metadata", "spec"],
        content_types=["text/yaml", "text/plain"],
    ),
    PathDefinition(
        path="docker-compose.production.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Production Docker Compose exposed",
        signatures=["services", "volumes", "networks"],
        content_types=["text/yaml", "text/plain"],
    ),
    PathDefinition(
        path=".dockerignore",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Docker ignore file exposed (reveals project structure)",
        signatures=["node_modules", ".git", "*.log"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="skaffold.yaml",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Skaffold configuration exposed",
        signatures=["apiVersion", "kind", "build", "deploy"],
        content_types=["text/yaml"],
    ),
    PathDefinition(
        path="helmfile.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Helmfile configuration exposed",
        signatures=["releases", "repositories", "environments"],
        content_types=["text/yaml"],
    ),

    # --------------------------------------------------------
    # API DOCUMENTATION (Attack Surface Mapping)
    # --------------------------------------------------------
    PathDefinition(
        path="api/v1/openapi.json",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="OpenAPI v3 specification exposed",
        signatures=["openapi", "paths", "components"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="docs/swagger.json",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Swagger documentation exposed",
        signatures=["swagger", "paths", "definitions"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="api/docs",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="API documentation endpoint",
        signatures=["swagger", "api", "documentation"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="graphql/schema",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="GraphQL schema exposed",
        signatures=["type", "Query", "Mutation", "schema"],
        content_types=["text/plain", "application/json"],
    ),
    PathDefinition(
        path="graphiql",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="GraphiQL IDE exposed",
        signatures=["graphiql", "GraphQL", "query"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="playground",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="GraphQL Playground exposed",
        signatures=["playground", "GraphQL", "endpoint"],
        content_types=["text/html"],
    ),

    # --------------------------------------------------------
    # DEBUG & MONITORING ENDPOINTS
    # --------------------------------------------------------
    PathDefinition(
        path="actuator/env",
        category=Category.DEBUG,
        severity=Severity.CRITICAL,
        description="Spring Boot Actuator environment exposed",
        signatures=["activeProfiles", "propertySources", "systemEnvironment"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="actuator/configprops",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="Spring Boot Actuator config properties exposed",
        signatures=["contexts", "beans", "properties"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="actuator/heapdump",
        category=Category.DEBUG,
        severity=Severity.CRITICAL,
        description="Spring Boot heap dump exposed (contains secrets)",
        signatures=[],
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path="actuator/threaddump",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        description="Spring Boot thread dump exposed",
        signatures=["threads", "threadName", "stackTrace"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="metrics",
        category=Category.DEBUG,
        severity=Severity.LOW,
        description="Prometheus metrics endpoint",
        signatures=["# HELP", "# TYPE", "_total", "_bucket"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="_debug",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="Debug endpoint exposed",
        signatures=["debug", "trace", "config"],
        content_types=["text/html", "application/json"],
    ),
    PathDefinition(
        path="elmah.axd",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="ELMAH error log viewer (.NET)",
        signatures=["ELMAH", "Error", "Exception"],
        content_types=["text/html"],
    ),
    PathDefinition(
        path="trace.axd",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        description="ASP.NET trace viewer",
        signatures=["Trace", "Request", "Response"],
        content_types=["text/html"],
    ),

    # --------------------------------------------------------
    # PACKAGE MANAGER FILES
    # --------------------------------------------------------
    PathDefinition(
        path="package-lock.json",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="NPM package lock file (reveals exact versions)",
        signatures=["lockfileVersion", "dependencies", "node_modules"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="yarn.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Yarn lock file exposed",
        signatures=["# yarn lockance", "resolved", "integrity"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="pnpm-lock.yaml",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="pnpm lock file exposed",
        signatures=["lockfileVersion", "dependencies", "specifiers"],
        content_types=["text/yaml"],
    ),
    PathDefinition(
        path="composer.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Composer lock file exposed",
        signatures=["_readme", "packages", "content-hash"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="Pipfile.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Pipfile lock exposed",
        signatures=["_meta", "default", "develop"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="poetry.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Poetry lock file exposed",
        signatures=["[[package]]", "name =", "version ="],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="Gemfile.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Bundler lock file exposed",
        signatures=["GEM", "BUNDLED", "DEPENDENCIES"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="go.sum",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Go module checksums exposed",
        signatures=["h1:", "go.sum"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="Cargo.lock",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="Rust Cargo lock file exposed",
        signatures=["[[package]]", "name =", "checksum ="],
        content_types=["text/plain"],
    ),

    # --------------------------------------------------------
    # IDE & EDITOR CONFIGURATIONS
    # --------------------------------------------------------
    PathDefinition(
        path=".idea/dataSources.xml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="IntelliJ database connection configuration",
        signatures=["data-source", "jdbc", "password"],
        content_types=["text/xml", "application/xml"],
    ),
    PathDefinition(
        path=".idea/dataSources.local.xml",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="IntelliJ database passwords",
        signatures=["database", "password", "master-password"],
        content_types=["text/xml"],
    ),
    PathDefinition(
        path=".vscode/launch.json",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="VS Code debug configuration",
        signatures=["configurations", "type", "request"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path=".vscode/tasks.json",
        category=Category.CONFIG,
        severity=Severity.LOW,
        description="VS Code tasks configuration",
        signatures=["tasks", "type", "command"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path=".editorconfig",
        category=Category.SENSITIVE,
        severity=Severity.LOW,
        description="EditorConfig file exposed",
        signatures=["root =", "indent_style", "indent_size"],
        content_types=["text/plain"],
    ),

    # --------------------------------------------------------
    # SECRETS & CREDENTIALS
    # --------------------------------------------------------
    PathDefinition(
        path=".npmrc",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="NPM configuration (may contain auth tokens)",
        signatures=["registry", "//registry", "_authToken"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".pypirc",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="PyPI configuration with credentials",
        signatures=["[pypi]", "username", "password"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".netrc",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Network credentials file",
        signatures=["machine", "login", "password"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".pgpass",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="PostgreSQL password file",
        signatures=[":5432:", ":postgres:"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".my.cnf",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="MySQL configuration with credentials",
        signatures=["[client]", "password", "user"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="id_rsa",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Private SSH key exposed",
        signatures=["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"],
        content_types=["text/plain", "application/octet-stream"],
    ),
    PathDefinition(
        path="id_ed25519",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="ED25519 private key exposed",
        signatures=["-----BEGIN OPENSSH PRIVATE KEY-----"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".ssh/id_rsa",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="SSH private key exposed",
        signatures=["-----BEGIN", "PRIVATE KEY"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="server.key",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="SSL/TLS private key exposed",
        signatures=["-----BEGIN", "PRIVATE KEY"],
        content_types=["text/plain"],
    ),

    # --------------------------------------------------------
    # VERCEL / NETLIFY / SERVERLESS
    # --------------------------------------------------------
    PathDefinition(
        path="vercel.json",
        category=Category.CONFIG,
        severity=Severity.LOW,
        description="Vercel configuration exposed",
        signatures=["builds", "routes", "env"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="netlify.toml",
        category=Category.CONFIG,
        severity=Severity.LOW,
        description="Netlify configuration exposed",
        signatures=["[build]", "command", "publish"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path="serverless.yml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Serverless Framework configuration",
        signatures=["service:", "provider:", "functions:"],
        content_types=["text/yaml", "text/plain"],
    ),
    PathDefinition(
        path="serverless.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Serverless Framework configuration",
        signatures=["service:", "provider:", "functions:"],
        content_types=["text/yaml"],
    ),
    PathDefinition(
        path="sam.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="AWS SAM template exposed",
        signatures=["AWSTemplateFormatVersion", "Transform", "Resources"],
        content_types=["text/yaml"],
    ),

    # --------------------------------------------------------
    # ADDITIONAL BACKUP PATTERNS
    # --------------------------------------------------------
    PathDefinition(
        path="backup.sql.gz",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Compressed SQL backup exposed",
        signatures=[],
        content_types=["application/gzip", "application/x-gzip"],
    ),
    PathDefinition(
        path="db_backup.sql",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Database backup file exposed",
        signatures=["INSERT INTO", "CREATE TABLE"],
        content_types=["text/plain", "application/sql"],
    ),
    PathDefinition(
        path="latest.dump",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="PostgreSQL dump file exposed",
        signatures=["PGDMP", "PostgreSQL"],
        content_types=["application/octet-stream"],
    ),
    PathDefinition(
        path="www.zip",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Website backup archive exposed",
        signatures=["PK"],
        content_types=["application/zip"],
    ),
    PathDefinition(
        path="website.zip",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Website backup archive exposed",
        signatures=["PK"],
        content_types=["application/zip"],
    ),
    PathDefinition(
        path="public_html.zip",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Public HTML backup exposed",
        signatures=["PK"],
        content_types=["application/zip"],
    ),

    # --------------------------------------------------------
    # v0.2 — EMPIRICAL AI-TOOL CONFIG PATHS
    # Derived from public threat intelligence and real-world leak observations.
    # --------------------------------------------------------

    # Continue.dev VS Code AI extension
    PathDefinition(
        path=".continue/agents/new-config.yaml",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Continue.dev VS Code AI extension agent config (often contains AI provider keys)",
        signatures=["models:", "apiKey", "provider:"],
        content_types=["text/yaml", "application/x-yaml", "text/plain"],
    ),
    PathDefinition(
        path=".continue/config.yaml",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Continue.dev primary config file",
        signatures=["models:", "apiKey"],
        content_types=["text/yaml", "application/x-yaml", "text/plain"],
    ),
    # Claude Code credentials
    PathDefinition(
        path="claude/.credentials.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="Claude Code credentials file",
        signatures=["sk-ant-"],
        content_types=["application/json"],
    ),
    # MCP server configs
    PathDefinition(
        path="mcp.json",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="MCP server configuration",
        signatures=["mcpServers", "command"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path=".cursor/mcp.json",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Cursor IDE MCP server configuration",
        signatures=["mcpServers"],
        content_types=["application/json"],
    ),
    # .NET build output (frequently committed accidentally)
    PathDefinition(
        path="bin/Debug/net8.0/appsettings.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description=".NET build output containing appsettings",
        signatures=["ConnectionStrings", "ApiKey"],
        content_types=["application/json"],
    ),
    PathDefinition(
        path="bin/Release/net8.0/appsettings.json",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description=".NET release build output containing appsettings",
        signatures=["ConnectionStrings", "ApiKey"],
        content_types=["application/json"],
    ),
    # Drizzle ORM
    PathDefinition(
        path="drizzle.config.ts",
        category=Category.CONFIG,
        severity=Severity.MEDIUM,
        description="Drizzle ORM config (may contain DB and AI keys)",
        signatures=["dbCredentials", "schema"],
        content_types=["application/typescript", "text/plain"],
    ),
    # CrewAI
    PathDefinition(
        path="agents.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="CrewAI agent definitions",
        signatures=["llm:", "role:", "goal:"],
        content_types=["text/yaml", "application/x-yaml"],
    ),
    PathDefinition(
        path="tasks.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="CrewAI task definitions",
        signatures=["agent:", "expected_output:"],
        content_types=["text/yaml", "application/x-yaml"],
    ),
    PathDefinition(
        path="crew.yaml",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="CrewAI crew definition",
        signatures=["agents:", "tasks:"],
        content_types=["text/yaml", "application/x-yaml"],
    ),
    # AutoGen
    PathDefinition(
        path="OAI_CONFIG_LIST",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="AutoGen API config list (multi-provider key aggregator)",
        signatures=["api_key", "model"],
        content_types=["application/json", "text/plain"],
    ),
    # LiteLLM proxy
    PathDefinition(
        path="litellm_config.yaml",
        category=Category.CONFIG,
        severity=Severity.CRITICAL,
        description="LiteLLM gateway config (multi-provider credentials)",
        signatures=["model_list", "api_key"],
        content_types=["text/yaml", "application/x-yaml"],
    ),
    # .env example/backup variants (frequently contain real keys despite name)
    PathDefinition(
        path=".env.local.example",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Example env file (frequently contains real keys despite name)",
        signatures=["API_KEY", "SECRET", "TOKEN"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.production.example",
        category=Category.ENV,
        severity=Severity.CRITICAL,
        description="Example production env file (frequently contains real keys)",
        signatures=["API_KEY", "SECRET", "TOKEN"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.bak",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Backup .env file",
        signatures=["API_KEY", "SECRET", "TOKEN"],
        content_types=["text/plain"],
    ),
    PathDefinition(
        path=".env.local.bak",
        category=Category.BACKUP,
        severity=Severity.CRITICAL,
        description="Backup .env.local file",
        signatures=["API_KEY", "SECRET", "TOKEN"],
        content_types=["text/plain"],
    ),
    # Firebase config (contains Firebase API key)
    PathDefinition(
        path="firebase-config.js",
        category=Category.CONFIG,
        severity=Severity.HIGH,
        description="Firebase client config (contains Firebase API key)",
        signatures=["apiKey", "authDomain", "projectId"],
        content_types=["application/javascript", "text/javascript"],
    ),
]


def get_extended_paths() -> List[PathDefinition]:
    """Return all extended sensitive paths."""
    return EXTENDED_PATHS


def get_all_paths_combined() -> List[PathDefinition]:
    """
    Return combined paths from both main and extended databases.
    
    Import the main paths and combine with extended paths.
    """
    from .paths import get_all_paths

    main_paths = get_all_paths()
    extended = get_extended_paths()

    # Combine and deduplicate by path
    seen_paths = set()
    combined = []

    for path_def in main_paths + extended:
        if path_def.path not in seen_paths:
            seen_paths.add(path_def.path)
            combined.append(path_def)

    return combined


def get_framework_specific_paths(framework: str) -> List[PathDefinition]:
    """
    Get paths specific to a framework.
    
    Args:
        framework: Framework name (nextjs, nuxt, vite, etc.)
        
    Returns:
        List of PathDefinitions for that framework
    """
    framework_keywords = {
        'nextjs': ['next', '_next'],
        'nuxt': ['nuxt', '.nuxt'],
        'vite': ['vite', '.vite'],
        'react': ['react', 'jsx'],
        'vue': ['vue', '.vue'],
        'angular': ['angular', 'ng'],
        'svelte': ['svelte'],
        'remix': ['remix'],
        'spring': ['actuator', 'spring'],
        'django': ['django', 'settings.py'],
        'rails': ['rails', 'ruby'],
        'laravel': ['laravel', 'artisan'],
    }

    keywords = framework_keywords.get(framework.lower(), [])
    if not keywords:
        return []

    return [
        p for p in EXTENDED_PATHS
        if any(kw.lower() in p.path.lower() or kw.lower() in p.description.lower()
               for kw in keywords)
    ]
