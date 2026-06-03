#!/usr/bin/env python3
"""
Credence MCP (Model Context Protocol) Server

Implements the Model Context Protocol to expose Credence as a set of
callable tools for AI agents (Claude, GPT, etc.). This enables:

- Autonomous security scanning by AI agents
- Integration with AI-powered security workflows
- Orchestration with other MCP-compatible tools (HexStrike AI pattern)

The MCP server exposes Credence's capabilities as structured tools:
- scan: Comprehensive web target scanning
- git_dump: Exposed git repository reconstruction
- secret_extract: Credential extraction and validation
- react2shell_detect: React2Shell vulnerability detection
- ml_model_scan: ML model supply chain scanning
- llm_exposure_scan: AI/LLM infrastructure detection
- unicode_detect: Invisible Unicode detection

Author: Credence Security Research
"""

import asyncio
import json
import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union


class ToolType(Enum):
    """Types of tools exposed via MCP"""
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    DETECTOR = "detector"
    EXTRACTOR = "extractor"


@dataclass
class ToolParameter:
    """Parameter definition for MCP tool"""
    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[List[str]] = None


@dataclass
class ToolDefinition:
    """Definition of an MCP tool"""
    name: str
    description: str
    parameters: List[ToolParameter]
    tool_type: ToolType
    returns: str
    examples: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ToolResult:
    """Result from tool execution"""
    success: bool
    tool_name: str
    result: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPRequest:
    """Incoming MCP request"""
    jsonrpc: str
    id: Union[str, int]
    method: str
    params: Optional[Dict[str, Any]] = None


@dataclass
class MCPResponse:
    """MCP response"""
    jsonrpc: str = "2.0"
    id: Union[str, int, None] = None
    result: Any = None
    error: Optional[Dict[str, Any]] = None


class CredenceMCPServer:
    """
    MCP Server that exposes Credence tools to AI agents.
    
    Implements JSON-RPC 2.0 over stdio for MCP communication.
    
    Usage with Claude/Cursor:
    ```json
    {
        "mcpServers": {
            "credence": {
                "command": "python",
                "args": ["-m", "credence.mcp_server"]
            }
        }
    }
    ```
    """

    VERSION = "1.0.0"

    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.tool_definitions: Dict[str, ToolDefinition] = {}

        # Register all Credence tools
        self._register_tools()

    def _register_tools(self):
        """Register all available tools"""

        # Comprehensive scan tool
        self._register_tool(
            ToolDefinition(
                name="credence_scan",
                description="Comprehensive scan for exposed sensitive files including .git directories, environment files, backups, configs, and more. Returns vulnerability findings with severity levels.",
                parameters=[
                    ToolParameter("target", "string", "Target URL or domain to scan"),
                    ToolParameter("concurrency", "integer", "Max concurrent requests (default: 50)", required=False, default=50),
                    ToolParameter("timeout", "integer", "Request timeout in seconds (default: 10)", required=False, default=10),
                    ToolParameter("follow_redirects", "boolean", "Follow HTTP redirects", required=False, default=False),
                ],
                tool_type=ToolType.SCANNER,
                returns="List of vulnerability findings with URLs, severity, and evidence",
                examples=[
                    {"target": "example.com", "concurrency": 30},
                    {"target": "https://api.example.com", "timeout": 15},
                ]
            ),
            self._execute_scan
        )

        # Git repository dumper
        self._register_tool(
            ToolDefinition(
                name="credence_git_dump",
                description="Download and reconstruct exposed .git repositories. Extracts source code, commit history, and scans for secrets in git history.",
                parameters=[
                    ToolParameter("target", "string", "Target URL with exposed .git directory"),
                    ToolParameter("output_dir", "string", "Directory to save the dumped repository", required=False, default="./git-dumps"),
                    ToolParameter("analyze_secrets", "boolean", "Scan git history for secrets", required=False, default=True),
                ],
                tool_type=ToolType.EXTRACTOR,
                returns="Dump results including downloaded files, reconstructed source, and found secrets",
                examples=[
                    {"target": "https://vulnerable-site.com/.git/"},
                ]
            ),
            self._execute_git_dump
        )

        # Secret extraction
        self._register_tool(
            ToolDefinition(
                name="credence_extract_secrets",
                description="Extract and optionally validate credentials from content. Detects AWS keys, API tokens, database URLs, private keys, and 30+ secret types.",
                parameters=[
                    ToolParameter("content", "string", "Text content to analyze for secrets"),
                    ToolParameter("validate", "boolean", "Attempt to validate discovered secrets", required=False, default=False),
                    ToolParameter("source", "string", "Optional source identifier (e.g., file path)", required=False),
                ],
                tool_type=ToolType.EXTRACTOR,
                returns="List of extracted secrets with type, value (masked), and validation status",
                examples=[
                    {"content": "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "validate": False},
                ]
            ),
            self._execute_secret_extraction
        )

        # React2Shell detection
        self._register_tool(
            ToolDefinition(
                name="credence_react2shell_detect",
                description="Detect React2Shell (CVE-2025-55182) vulnerability in Next.js/React applications. Scans for exposed RSC endpoints, Flight protocol, and vulnerable configurations.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for React2Shell vulnerability"),
                    ToolParameter("deep_scan", "boolean", "Perform deep scanning including version extraction", required=False, default=True),
                ],
                tool_type=ToolType.DETECTOR,
                returns="Vulnerability assessment with status, evidence, and recommendations",
                examples=[
                    {"target": "https://nextjs-app.example.com", "deep_scan": True},
                ]
            ),
            self._execute_react2shell_detect
        )

        # ML model scanning
        self._register_tool(
            ToolDefinition(
                name="credence_ml_model_scan",
                description="Scan for exposed ML model files that could contain malicious payloads. Detects pickle, PyTorch, TensorFlow, and ONNX models with RCE potential.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for exposed ML models"),
                    ToolParameter("deep_analysis", "boolean", "Download and analyze model content for malicious indicators", required=False, default=True),
                ],
                tool_type=ToolType.SCANNER,
                returns="List of exposed models with format, risk level, and malicious indicators",
                examples=[
                    {"target": "https://ml-api.example.com", "deep_analysis": True},
                ]
            ),
            self._execute_ml_model_scan
        )

        # LLM/RAG exposure scanning
        self._register_tool(
            ToolDefinition(
                name="credence_llm_exposure_scan",
                description="Scan for exposed AI/LLM infrastructure including vector databases, system prompts, RAG configurations, and API keys.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for LLM/RAG exposure"),
                ],
                tool_type=ToolType.SCANNER,
                returns="List of exposed AI infrastructure with severity and extracted data",
                examples=[
                    {"target": "https://ai-app.example.com"},
                ]
            ),
            self._execute_llm_exposure_scan
        )

        # Invisible Unicode detection
        self._register_tool(
            ToolDefinition(
                name="credence_unicode_detect",
                description="Detect invisible Unicode characters used in supply chain attacks (GlassWorm pattern). Scans for variation selectors, zero-width chars, bidirectional overrides, and homoglyphs.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for invisible Unicode"),
                    ToolParameter("content", "string", "Direct content to analyze (alternative to target)", required=False),
                ],
                tool_type=ToolType.DETECTOR,
                returns="Analysis of invisible Unicode anomalies with threat levels",
                examples=[
                    {"target": "https://vulnerable-site.com/bundle.js"},
                ]
            ),
            self._execute_unicode_detect
        )

        # Source map analysis
        self._register_tool(
            ToolDefinition(
                name="credence_sourcemap_scan",
                description="Detect and analyze exposed JavaScript source maps. Can recover original source code from .map files.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for source maps"),
                    ToolParameter("extract_sources", "boolean", "Extract original source code from maps", required=False, default=True),
                ],
                tool_type=ToolType.ANALYZER,
                returns="List of discovered source maps with extracted file listings",
                examples=[
                    {"target": "https://webapp.example.com", "extract_sources": True},
                ]
            ),
            self._execute_sourcemap_scan
        )

        # CI/CD exposure scanning
        self._register_tool(
            ToolDefinition(
                name="credence_cicd_scan",
                description="Scan for exposed CI/CD pipeline configurations, logs, and artifacts. Detects GitHub Actions, GitLab CI, Jenkins, and other pipeline configs.",
                parameters=[
                    ToolParameter("target", "string", "Target URL to scan for CI/CD exposure"),
                ],
                tool_type=ToolType.SCANNER,
                returns="List of exposed CI/CD configurations with secrets and misconfigurations",
                examples=[
                    {"target": "https://repo.example.com"},
                ]
            ),
            self._execute_cicd_scan
        )

        # API discovery
        self._register_tool(
            ToolDefinition(
                name="credence_api_discovery",
                description="Discover and analyze API endpoints including GraphQL introspection, OpenAPI/Swagger specs, and REST endpoint enumeration.",
                parameters=[
                    ToolParameter("target", "string", "Target URL for API discovery"),
                    ToolParameter("graphql_introspection", "boolean", "Attempt GraphQL introspection", required=False, default=True),
                ],
                tool_type=ToolType.ANALYZER,
                returns="Discovered API endpoints and schema information",
                examples=[
                    {"target": "https://api.example.com", "graphql_introspection": True},
                ]
            ),
            self._execute_api_discovery
        )

    def _register_tool(self, definition: ToolDefinition, handler: Callable):
        """Register a tool with its handler"""
        self.tools[definition.name] = handler
        self.tool_definitions[definition.name] = definition

    # Tool execution methods

    async def _execute_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive scan"""
        try:
            # Import scanner (lazy import to avoid circular deps)
            from .scanner import CredenceScanner

            target = params["target"]
            concurrency = params.get("concurrency", 50)
            timeout = params.get("timeout", 10)

            scanner = CredenceScanner(concurrency=concurrency, timeout=timeout)
            report = scanner.scan_sync([target])

            # Convert to dict
            findings = []
            for target_report in report.target_reports:
                for finding in target_report.findings:
                    findings.append({
                        "url": finding.url,
                        "path": finding.path,
                        "severity": finding.severity,
                        "category": finding.category,
                        "description": finding.description,
                        "evidence": finding.evidence[:200] if finding.evidence else None,
                    })

            return {
                "target": target,
                "findings_count": len(findings),
                "findings": findings,
                "scan_duration": report.duration,
            }
        except ImportError:
            return await self._fallback_scan(params)
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")

    async def _fallback_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback scan using basic HTTP checks"""
        import aiohttp

        target = params["target"]
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        findings = []
        paths_to_check = [
            ("/.git/config", "critical", "git"),
            ("/.git/HEAD", "critical", "git"),
            ("/.env", "critical", "env"),
            ("/.env.local", "critical", "env"),
            ("/config.json", "high", "config"),
            ("/package.json", "medium", "config"),
        ]

        async with aiohttp.ClientSession() as session:
            for path, severity, category in paths_to_check:
                try:
                    url = f"{target.rstrip('/')}{path}"
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            if len(content) > 10:
                                findings.append({
                                    "url": url,
                                    "path": path,
                                    "severity": severity,
                                    "category": category,
                                    "status_code": resp.status,
                                })
                except Exception:
                    continue

        return {
            "target": target,
            "findings_count": len(findings),
            "findings": findings,
        }

    async def _execute_git_dump(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute git repository dump"""
        try:
            from pathlib import Path

            import aiohttp

            from .git_dumper import GitDumper

            target = params["target"]
            output_dir = Path(params.get("output_dir", "./git-dumps"))
            analyze_secrets = params.get("analyze_secrets", True)

            async with aiohttp.ClientSession() as session:
                dumper = GitDumper(target, output_dir, session)
                result = await dumper.dump()

            return {
                "success": result.get("success", False),
                "files_downloaded": result.get("files_downloaded", 0),
                "output_directory": str(output_dir),
                "secrets_found": len(result.get("secrets_found", [])),
                "secrets": result.get("secrets_found", [])[:10],  # Limit for response size
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    async def _execute_secret_extraction(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute secret extraction"""
        try:
            from ..secrets.secret_extractor import SecretExtractor

            content = params["content"]
            validate = params.get("validate", False)
            source = params.get("source", "unknown")

            extractor = SecretExtractor(validate=validate)
            secrets = await extractor.extract(content)

            # Mask secrets for safety
            masked_secrets = []
            for secret in secrets:
                masked = {
                    "type": secret["type"],
                    "value_masked": secret["value"][:8] + "..." + secret["value"][-4:] if len(secret["value"]) > 12 else "***",
                    "line": secret.get("line"),
                    "valid": secret.get("validated"),
                }
                masked_secrets.append(masked)

            return {
                "source": source,
                "secrets_found": len(masked_secrets),
                "secrets": masked_secrets,
            }
        except Exception as e:
            return {
                "secrets_found": 0,
                "error": str(e),
            }

    async def _execute_react2shell_detect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute React2Shell detection"""
        try:
            from .react2shell_detector import React2ShellDetector

            target = params["target"]
            deep_scan = params.get("deep_scan", True)

            detector = React2ShellDetector(deep_scan=deep_scan)
            finding = await detector.scan(target)

            return {
                "target": target,
                "status": finding.status.value,
                "framework": finding.framework.value,
                "framework_version": finding.framework_version,
                "risk_score": finding.risk_score,
                "evidence": finding.evidence,
                "endpoints_found": len(finding.endpoints),
                "recommendations": finding.recommendations,
                "cve_id": finding.cve_id,
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

    async def _execute_ml_model_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ML model scan"""
        try:
            from .ml_model_scanner import MLModelScanner

            target = params["target"]
            deep_analysis = params.get("deep_analysis", True)

            scanner = MLModelScanner(deep_analysis=deep_analysis)
            result = await scanner.scan(target)

            exposed_models = []
            for model in result.exposed_models:
                exposed_models.append({
                    "url": model.url,
                    "path": model.path,
                    "format": model.format.value,
                    "size": model.size,
                    "risk_level": model.risk_level.value,
                    "indicators_count": len(model.indicators),
                })

            return {
                "target": target,
                "exposed_models_count": len(exposed_models),
                "exposed_models": exposed_models,
                "total_risk_score": result.total_risk_score,
                "recommendations": result.recommendations,
            }
        except Exception as e:
            return {
                "exposed_models_count": 0,
                "error": str(e),
            }

    async def _execute_llm_exposure_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute LLM/RAG exposure scan"""
        try:
            from .llm_exposure_scanner import LLMExposureScanner

            target = params["target"]

            scanner = LLMExposureScanner()
            result = await scanner.scan(target)

            exposures = []
            for exp in result.exposures:
                exposures.append({
                    "url": exp.url,
                    "type": exp.exposure_type.value,
                    "severity": exp.severity.value,
                    "description": exp.description,
                    "evidence": exp.evidence[:3],
                })

            return {
                "target": target,
                "exposures_count": len(exposures),
                "exposures": exposures,
                "detected_technologies": result.detected_technologies,
                "total_risk_score": result.total_risk_score,
                "recommendations": result.recommendations,
            }
        except Exception as e:
            return {
                "exposures_count": 0,
                "error": str(e),
            }

    async def _execute_unicode_detect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute invisible Unicode detection"""
        try:
            from .invisible_unicode_detector import (
                InvisibleUnicodeAnalyzer,
                InvisibleUnicodeScanner,
            )

            if "content" in params and params["content"]:
                # Direct content analysis
                analyzer = InvisibleUnicodeAnalyzer()
                anomalies = analyzer.analyze(params["content"])

                return {
                    "source": "direct_content",
                    "anomalies_count": len(anomalies),
                    "anomalies": [
                        {
                            "category": a.category.value,
                            "threat_level": a.threat_level.value,
                            "codepoint": a.codepoint,
                            "line": a.line_number,
                            "description": a.description,
                        }
                        for a in anomalies[:20]
                    ],
                }
            else:
                # URL scanning
                target = params["target"]
                scanner = InvisibleUnicodeScanner()
                result = await scanner.scan(target)

                return {
                    "target": target,
                    "files_analyzed": len(result.analyzed_files),
                    "total_anomalies": result.total_anomalies,
                    "critical_findings": result.critical_findings,
                    "recommendations": result.recommendations,
                }
        except Exception as e:
            return {
                "anomalies_count": 0,
                "error": str(e),
            }

    async def _execute_sourcemap_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute source map scan"""
        try:
            from .sourcemap_analyzer import SourceMapAnalyzer

            target = params["target"]
            extract_sources = params.get("extract_sources", True)

            analyzer = SourceMapAnalyzer()
            result = await analyzer.scan(target)

            return {
                "target": target,
                "sourcemaps_found": len(result.get("sourcemaps", [])),
                "sourcemaps": result.get("sourcemaps", []),
                "total_files_recovered": result.get("total_files", 0),
            }
        except Exception as e:
            return {
                "sourcemaps_found": 0,
                "error": str(e),
            }

    async def _execute_cicd_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute CI/CD exposure scan"""
        try:
            from .cicd_scanner import CICDScanner

            target = params["target"]

            scanner = CICDScanner()
            result = await scanner.scan(target)

            return {
                "target": target,
                "findings_count": len(result.get("findings", [])),
                "findings": result.get("findings", []),
                "secrets_found": result.get("secrets_count", 0),
            }
        except Exception as e:
            return {
                "findings_count": 0,
                "error": str(e),
            }

    async def _execute_api_discovery(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API discovery"""
        try:
            from .api_discovery import APIDiscovery

            target = params["target"]
            graphql_introspection = params.get("graphql_introspection", True)

            discovery = APIDiscovery()
            result = await discovery.discover(target, graphql_introspection=graphql_introspection)

            return {
                "target": target,
                "endpoints_discovered": len(result.get("endpoints", [])),
                "endpoints": result.get("endpoints", [])[:50],  # Limit response
                "graphql_schema": result.get("graphql_schema"),
                "openapi_spec": result.get("openapi_spec") is not None,
            }
        except Exception as e:
            return {
                "endpoints_discovered": 0,
                "error": str(e),
            }

    # MCP Protocol Methods

    async def handle_request(self, request: MCPRequest) -> MCPResponse:
        """Handle incoming MCP request"""
        try:
            if request.method == "initialize":
                return await self._handle_initialize(request)
            elif request.method == "tools/list":
                return await self._handle_tools_list(request)
            elif request.method == "tools/call":
                return await self._handle_tools_call(request)
            elif request.method == "resources/list":
                return await self._handle_resources_list(request)
            elif request.method == "shutdown":
                return MCPResponse(id=request.id, result={"success": True})
            else:
                return MCPResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Method not found: {request.method}"}
                )
        except Exception as e:
            return MCPResponse(
                id=request.id,
                error={"code": -32603, "message": str(e)}
            )

    async def _handle_initialize(self, request: MCPRequest) -> MCPResponse:
        """Handle initialize request"""
        return MCPResponse(
            id=request.id,
            result={
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": "credence",
                    "version": self.VERSION,
                    "description": "Security scanner for exposed sensitive files, git repositories, and AI infrastructure",
                }
            }
        )

    async def _handle_tools_list(self, request: MCPRequest) -> MCPResponse:
        """Handle tools/list request"""
        tools = []
        for name, definition in self.tool_definitions.items():
            tool_schema = {
                "name": name,
                "description": definition.description,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                }
            }

            for param in definition.parameters:
                tool_schema["inputSchema"]["properties"][param.name] = {
                    "type": param.type,
                    "description": param.description,
                }
                if param.enum:
                    tool_schema["inputSchema"]["properties"][param.name]["enum"] = param.enum
                if param.default is not None:
                    tool_schema["inputSchema"]["properties"][param.name]["default"] = param.default
                if param.required:
                    tool_schema["inputSchema"]["required"].append(param.name)

            tools.append(tool_schema)

        return MCPResponse(id=request.id, result={"tools": tools})

    async def _handle_tools_call(self, request: MCPRequest) -> MCPResponse:
        """Handle tools/call request"""
        params = request.params or {}
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if tool_name not in self.tools:
            return MCPResponse(
                id=request.id,
                error={"code": -32602, "message": f"Unknown tool: {tool_name}"}
            )

        try:
            import time
            start_time = time.time()

            handler = self.tools[tool_name]
            result = await handler(tool_args)

            execution_time = time.time() - start_time

            return MCPResponse(
                id=request.id,
                result={
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str)
                        }
                    ],
                    "isError": False,
                    "_meta": {
                        "execution_time": execution_time,
                        "tool": tool_name,
                    }
                }
            )
        except Exception as e:
            return MCPResponse(
                id=request.id,
                result={
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "error": str(e),
                                "traceback": traceback.format_exc()
                            })
                        }
                    ],
                    "isError": True,
                }
            )

    async def _handle_resources_list(self, request: MCPRequest) -> MCPResponse:
        """Handle resources/list request"""
        # Credence doesn't expose resources, only tools
        return MCPResponse(id=request.id, result={"resources": []})

    async def run_stdio(self):
        """Run server using stdio transport"""

        while True:
            try:
                # Read line from stdin
                line = await asyncio.get_event_loop().run_in_executor(
                    None, sys.stdin.readline
                )

                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse JSON-RPC request
                try:
                    data = json.loads(line)
                    request = MCPRequest(
                        jsonrpc=data.get("jsonrpc", "2.0"),
                        id=data.get("id"),
                        method=data["method"],
                        params=data.get("params")
                    )
                except json.JSONDecodeError as e:
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {e}"}
                    }
                    print(json.dumps(error_response), flush=True)
                    continue

                # Handle request
                response = await self.handle_request(request)

                # Send response
                response_dict = {
                    "jsonrpc": response.jsonrpc,
                    "id": response.id,
                }
                if response.result is not None:
                    response_dict["result"] = response.result
                if response.error is not None:
                    response_dict["error"] = response.error

                print(json.dumps(response_dict), flush=True)

                # Check for shutdown
                if request.method == "shutdown":
                    break

            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                }
                print(json.dumps(error_response), flush=True)


def main():
    """Main entry point for MCP server"""
    server = CredenceMCPServer()
    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
