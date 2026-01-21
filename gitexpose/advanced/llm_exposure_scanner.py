#!/usr/bin/env python3
"""
LLM/RAG Infrastructure Exposure Scanner

Detects exposed AI/LLM infrastructure including:
- Vector databases (ChromaDB, Pinecone, Weaviate, Milvus, Qdrant)
- RAG configurations and knowledge bases
- Prompt templates and system prompts
- LangChain/LlamaIndex configurations
- Model API configurations and keys
- Embedding endpoints

This addresses a critical gap in security tooling as organizations
rapidly deploy AI without adequate security controls.

Author: GitExpose Security Research
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp


class ExposureType(Enum):
    """Type of AI/LLM exposure"""
    VECTOR_DATABASE = "vector_database"
    SYSTEM_PROMPT = "system_prompt"
    RAG_CONFIG = "rag_configuration"
    API_KEYS = "api_keys"
    MODEL_CONFIG = "model_configuration"
    TRAINING_DATA = "training_data"
    EMBEDDINGS = "embeddings"
    LANGCHAIN = "langchain"
    LLAMAINDEX = "llamaindex"
    AGENT_CONFIG = "agent_configuration"


class Severity(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LLMExposure:
    """Represents an LLM/RAG exposure finding"""
    url: str
    exposure_type: ExposureType
    severity: Severity
    description: str
    evidence: List[str] = field(default_factory=list)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class LLMScanResult:
    """Complete scan result"""
    target: str
    exposures: List[LLMExposure]
    total_risk_score: float
    detected_technologies: List[str]
    recommendations: List[str]
    scan_duration: float = 0.0


class VectorDBDetector:
    """
    Detect exposed vector database endpoints and interfaces.
    
    Supports:
    - ChromaDB
    - Pinecone
    - Weaviate
    - Milvus
    - Qdrant
    - Elasticsearch with vector search
    - PostgreSQL with pgvector
    """

    # Vector DB endpoints and their signatures
    VECTOR_DB_SIGNATURES = {
        "chromadb": {
            "paths": [
                "/api/v1",
                "/api/v1/collections",
                "/api/v1/heartbeat",
                "/.chroma/",
                "/chroma/",
            ],
            "indicators": [
                '"chroma"',
                '"collections"',
                "chromadb",
            ],
            "severity": Severity.CRITICAL,
        },
        "pinecone": {
            "paths": [
                "/describe_index_stats",
                "/query",
                "/vectors/",
            ],
            "indicators": [
                "pinecone",
                "vector_count",
                "dimension",
            ],
            "severity": Severity.CRITICAL,
        },
        "weaviate": {
            "paths": [
                "/v1/schema",
                "/v1/objects",
                "/v1/.well-known/ready",
                "/v1/.well-known/live",
                "/v1/meta",
            ],
            "indicators": [
                "weaviate",
                '"classes"',
                "vectorizer",
            ],
            "severity": Severity.CRITICAL,
        },
        "milvus": {
            "paths": [
                "/api/v1/health",
                "/api/v1/collections",
                "/v1/vector/",
            ],
            "indicators": [
                "milvus",
                "collection_name",
            ],
            "severity": Severity.HIGH,
        },
        "qdrant": {
            "paths": [
                "/collections",
                "/cluster",
                "/telemetry",
            ],
            "indicators": [
                "qdrant",
                '"vectors_count"',
            ],
            "severity": Severity.CRITICAL,
        },
    }

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed vector databases"""
        exposures = []

        for db_name, config in self.VECTOR_DB_SIGNATURES.items():
            for path in config["paths"]:
                try:
                    url = urljoin(target, path)
                    async with semaphore:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                content = await resp.text()

                                # Check for indicators
                                if any(ind.lower() in content.lower() for ind in config["indicators"]):
                                    exposure = LLMExposure(
                                        url=url,
                                        exposure_type=ExposureType.VECTOR_DATABASE,
                                        severity=config["severity"],
                                        description=f"Exposed {db_name.upper()} vector database endpoint",
                                        evidence=[f"Endpoint accessible: {path}"],
                                        recommendations=[
                                            f"Restrict access to {db_name} API endpoints",
                                            "Implement authentication for vector database access",
                                            "Use network segmentation to isolate AI infrastructure",
                                        ]
                                    )

                                    # Try to extract collection/schema info
                                    extracted = self._extract_db_info(db_name, content)
                                    if extracted:
                                        exposure.extracted_data = extracted
                                        exposure.evidence.append(f"Extracted {len(extracted)} data points")

                                    exposures.append(exposure)
                                    break  # Found this DB, move to next
                except Exception:
                    continue

        return exposures

    def _extract_db_info(self, db_name: str, content: str) -> Dict[str, Any]:
        """Extract information from vector DB responses"""
        extracted = {}

        try:
            data = json.loads(content)

            if db_name == "chromadb":
                if isinstance(data, list):
                    extracted["collections"] = [c.get("name") for c in data if isinstance(c, dict)]
                    extracted["collection_count"] = len(data)

            elif db_name == "weaviate":
                if "classes" in data:
                    extracted["classes"] = [c.get("class") for c in data.get("classes", [])]
                    extracted["class_count"] = len(data.get("classes", []))

            elif db_name == "qdrant":
                if "collections" in data:
                    extracted["collections"] = list(data.get("collections", {}).keys())

            elif db_name == "pinecone":
                extracted["total_vector_count"] = data.get("totalVectorCount", data.get("vector_count"))
                extracted["dimension"] = data.get("dimension")
        except json.JSONDecodeError:
            pass

        return extracted


class PromptExposureDetector:
    """
    Detect exposed system prompts and prompt templates.
    
    System prompts often contain:
    - Business logic and rules
    - Internal API documentation
    - Confidential instructions
    - Security bypass information
    """

    # Paths where prompts might be exposed
    PROMPT_PATHS = [
        "/prompts/",
        "/prompt/",
        "/system_prompt",
        "/system-prompt",
        "/prompts/system.txt",
        "/prompts/system.md",
        "/prompts/system.json",
        "/prompts/base.txt",
        "/config/prompts.json",
        "/config/prompts.yaml",
        "/api/prompts",
        "/.prompts/",
        "/templates/prompts/",
        "/llm/prompts/",
        "/ai/prompts/",
    ]

    # Indicators of system prompts in content
    PROMPT_INDICATORS = [
        "you are a",
        "you are an",
        "your role is",
        "as an ai",
        "as a helpful",
        "system prompt",
        "instructions:",
        "your task is",
        "you must",
        "never reveal",
        "do not disclose",
        "confidential",
        "internal use only",
    ]

    # Sensitive patterns in prompts
    SENSITIVE_PATTERNS = [
        (r'api[_-]?key\s*[:=]\s*["\']?[\w-]+', "API key in prompt"),
        (r'password\s*[:=]\s*["\']?[\w-]+', "Password in prompt"),
        (r'secret\s*[:=]\s*["\']?[\w-]+', "Secret in prompt"),
        (r'token\s*[:=]\s*["\']?[\w-]+', "Token in prompt"),
        (r'internal[_-]?api', "Internal API reference"),
        (r'admin\s+endpoint', "Admin endpoint reference"),
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed prompts"""
        exposures = []

        for path in self.PROMPT_PATHS:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            content_lower = content.lower()

                            # Check for prompt indicators
                            matched_indicators = [
                                ind for ind in self.PROMPT_INDICATORS
                                if ind in content_lower
                            ]

                            if matched_indicators:
                                severity = Severity.HIGH
                                evidence = [f"Contains prompt indicators: {', '.join(matched_indicators[:3])}"]
                                extracted = {"preview": content[:500]}

                                # Check for sensitive patterns
                                for pattern, description in self.SENSITIVE_PATTERNS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        severity = Severity.CRITICAL
                                        evidence.append(f"Contains sensitive data: {description}")

                                exposures.append(LLMExposure(
                                    url=url,
                                    exposure_type=ExposureType.SYSTEM_PROMPT,
                                    severity=severity,
                                    description="Exposed system prompt or prompt template",
                                    evidence=evidence,
                                    extracted_data=extracted,
                                    recommendations=[
                                        "Remove publicly accessible prompt files",
                                        "Store prompts in secure, access-controlled locations",
                                        "Implement prompt versioning with access logging",
                                        "Review prompts for sensitive information leakage",
                                    ]
                                ))
            except Exception:
                continue

        return exposures


class RAGConfigDetector:
    """
    Detect exposed RAG (Retrieval-Augmented Generation) configurations.
    
    RAG configs may reveal:
    - Knowledge base locations
    - Embedding model configurations
    - Chunking strategies
    - Retrieval parameters
    """

    RAG_PATHS = [
        "/rag/config.json",
        "/rag/config.yaml",
        "/config/rag.json",
        "/config/rag.yaml",
        "/config/retrieval.json",
        "/.rag/",
        "/knowledge_base/",
        "/kb/",
        "/embeddings/config.json",
        "/vector_store/config.json",
    ]

    RAG_INDICATORS = [
        "chunk_size",
        "chunk_overlap",
        "embedding_model",
        "retriever",
        "knowledge_base",
        "vector_store",
        "similarity_threshold",
        "top_k",
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed RAG configurations"""
        exposures = []

        for path in self.RAG_PATHS:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            if any(ind in content.lower() for ind in self.RAG_INDICATORS):
                                extracted = {}
                                try:
                                    data = json.loads(content)
                                    extracted = {
                                        k: v for k, v in data.items()
                                        if k in self.RAG_INDICATORS
                                    }
                                except json.JSONDecodeError:
                                    pass

                                exposures.append(LLMExposure(
                                    url=url,
                                    exposure_type=ExposureType.RAG_CONFIG,
                                    severity=Severity.HIGH,
                                    description="Exposed RAG configuration",
                                    evidence=["RAG configuration parameters found"],
                                    extracted_data=extracted,
                                    recommendations=[
                                        "Secure RAG configuration files",
                                        "Use environment variables for sensitive RAG settings",
                                        "Implement access controls on knowledge base endpoints",
                                    ]
                                ))
            except Exception:
                continue

        return exposures


class LangChainDetector:
    """
    Detect exposed LangChain configurations and artifacts.
    
    LangChain deployments may expose:
    - Chain configurations
    - Tool definitions
    - Agent prompts
    - Memory stores
    """

    LANGCHAIN_PATHS = [
        "/langchain/",
        "/.langchain/",
        "/config/langchain.json",
        "/chains/",
        "/agents/",
        "/tools/",
        "/langserve/",
        "/api/langchain/",
    ]

    # LangSmith/LangServe endpoints
    LANGSMITH_PATHS = [
        "/runs/",
        "/feedback/",
        "/public/",
    ]

    LANGCHAIN_INDICATORS = [
        "langchain",
        "llm_chain",
        "agent_executor",
        "tool_calling",
        "memory",
        "callback",
        "langserve",
        "langsmith",
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed LangChain configurations"""
        exposures = []

        all_paths = self.LANGCHAIN_PATHS + self.LANGSMITH_PATHS

        for path in all_paths:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            if any(ind in content.lower() for ind in self.LANGCHAIN_INDICATORS):
                                is_langsmith = any(p in path for p in ['/runs/', '/feedback/'])

                                exposures.append(LLMExposure(
                                    url=url,
                                    exposure_type=ExposureType.LANGCHAIN,
                                    severity=Severity.HIGH if is_langsmith else Severity.MEDIUM,
                                    description=f"Exposed {'LangSmith' if is_langsmith else 'LangChain'} endpoint",
                                    evidence=[f"LangChain indicators found at {path}"],
                                    recommendations=[
                                        "Implement authentication for LangChain/LangServe endpoints",
                                        "Use API keys for LangSmith access",
                                        "Review exposed chain configurations for sensitive data",
                                    ]
                                ))
            except Exception:
                continue

        return exposures


class LlamaIndexDetector:
    """Detect exposed LlamaIndex configurations"""

    LLAMAINDEX_PATHS = [
        "/llamaindex/",
        "/.llamaindex/",
        "/index/",
        "/indices/",
        "/storage/",
        "/persist/",
        "/config/llamaindex.json",
    ]

    LLAMAINDEX_INDICATORS = [
        "llamaindex",
        "llama_index",
        "index_struct",
        "docstore",
        "vector_store",
        "index_store",
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed LlamaIndex configurations"""
        exposures = []

        for path in self.LLAMAINDEX_PATHS:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            if any(ind in content.lower() for ind in self.LLAMAINDEX_INDICATORS):
                                exposures.append(LLMExposure(
                                    url=url,
                                    exposure_type=ExposureType.LLAMAINDEX,
                                    severity=Severity.MEDIUM,
                                    description="Exposed LlamaIndex configuration or storage",
                                    evidence=["LlamaIndex indicators found"],
                                    recommendations=[
                                        "Secure LlamaIndex storage directories",
                                        "Implement access controls on index endpoints",
                                    ]
                                ))
            except Exception:
                continue

        return exposures


class APIKeyDetector:
    """
    Detect exposed LLM API keys and configurations.
    
    Targets:
    - OpenAI API keys
    - Anthropic API keys
    - Cohere API keys
    - HuggingFace tokens
    - Azure OpenAI configurations
    """

    # API key patterns
    API_KEY_PATTERNS = {
        "openai": (r'sk-[a-zA-Z0-9]{48}', Severity.CRITICAL),
        "openai_project": (r'sk-proj-[a-zA-Z0-9]{48}', Severity.CRITICAL),
        "anthropic": (r'sk-ant-[a-zA-Z0-9-]{32,}', Severity.CRITICAL),
        "cohere": (r'[a-zA-Z0-9]{40}', Severity.HIGH),  # Generic but often Cohere
        "huggingface": (r'hf_[a-zA-Z0-9]{34}', Severity.HIGH),
        "google_ai": (r'AIza[0-9A-Za-z\\-_]{35}', Severity.CRITICAL),
        "azure_openai": (r'[a-f0-9]{32}', Severity.HIGH),  # Azure API keys
    }

    # Configuration paths
    CONFIG_PATHS = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.json",
        "/config.yaml",
        "/settings.json",
        "/api/config",
        "/llm/config",
        "/openai/config",
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed API keys"""
        exposures = []

        for path in self.CONFIG_PATHS:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            for key_type, (pattern, severity) in self.API_KEY_PATTERNS.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    # Mask the keys for reporting
                                    masked = [m[:8] + "..." + m[-4:] for m in matches]

                                    exposures.append(LLMExposure(
                                        url=url,
                                        exposure_type=ExposureType.API_KEYS,
                                        severity=severity,
                                        description=f"Exposed {key_type.upper()} API key",
                                        evidence=[f"Found {len(matches)} {key_type} key(s)"],
                                        extracted_data={"masked_keys": masked},
                                        recommendations=[
                                            f"Immediately rotate the exposed {key_type} API key",
                                            "Remove API keys from publicly accessible files",
                                            "Use secret management solutions (Vault, AWS Secrets Manager)",
                                            "Implement API key usage monitoring",
                                        ]
                                    ))
            except Exception:
                continue

        return exposures


class AgentConfigDetector:
    """
    Detect exposed AI agent configurations.
    
    Agentic AI systems expose significant attack surface:
    - Tool definitions and permissions
    - MCP server configurations
    - Function calling schemas
    - Agent memory and state
    """

    AGENT_PATHS = [
        "/agents/",
        "/agent/config",
        "/mcp/",
        "/.mcp/",
        "/config/agents.json",
        "/tools/",
        "/functions/",
        "/skills/",
    ]

    AGENT_INDICATORS = [
        "agent",
        "tool_use",
        "function_calling",
        "mcp_server",
        "model_context_protocol",
        "skill",
        "action",
        "capability",
    ]

    async def detect(
        self,
        target: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore
    ) -> List[LLMExposure]:
        """Detect exposed agent configurations"""
        exposures = []

        for path in self.AGENT_PATHS:
            try:
                url = urljoin(target, path)
                async with semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            if any(ind in content.lower() for ind in self.AGENT_INDICATORS):
                                exposures.append(LLMExposure(
                                    url=url,
                                    exposure_type=ExposureType.AGENT_CONFIG,
                                    severity=Severity.HIGH,
                                    description="Exposed AI agent configuration",
                                    evidence=["Agent configuration indicators found"],
                                    recommendations=[
                                        "Secure agent configuration endpoints",
                                        "Implement principle of least privilege for agent tools",
                                        "Audit agent capabilities and permissions",
                                        "Monitor agent actions and tool usage",
                                    ]
                                ))
            except Exception:
                continue

        return exposures


class LLMExposureScanner:
    """
    Comprehensive scanner for LLM/RAG infrastructure exposure.
    
    Orchestrates all detectors to provide complete visibility
    into exposed AI infrastructure.
    """

    def __init__(
        self,
        timeout: int = 15,
        max_concurrent: int = 20,
        verify_ssl: bool = False
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Initialize all detectors
        self.vector_db_detector = VectorDBDetector()
        self.prompt_detector = PromptExposureDetector()
        self.rag_detector = RAGConfigDetector()
        self.langchain_detector = LangChainDetector()
        self.llamaindex_detector = LlamaIndexDetector()
        self.api_key_detector = APIKeyDetector()
        self.agent_detector = AgentConfigDetector()

    async def scan(
        self,
        target: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> LLMScanResult:
        """
        Perform comprehensive LLM/RAG exposure scan.
        """
        import time
        start_time = time.time()

        own_session = session is None
        if own_session:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=self.max_concurrent)
            session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)

        try:
            target = self._normalize_url(target)

            # Run all detectors concurrently
            results = await asyncio.gather(
                self.vector_db_detector.detect(target, session, self.semaphore),
                self.prompt_detector.detect(target, session, self.semaphore),
                self.rag_detector.detect(target, session, self.semaphore),
                self.langchain_detector.detect(target, session, self.semaphore),
                self.llamaindex_detector.detect(target, session, self.semaphore),
                self.api_key_detector.detect(target, session, self.semaphore),
                self.agent_detector.detect(target, session, self.semaphore),
                return_exceptions=True
            )

            # Flatten results
            all_exposures = []
            detected_tech = set()

            for result in results:
                if isinstance(result, list):
                    all_exposures.extend(result)
                    for exp in result:
                        detected_tech.add(exp.exposure_type.value)

            # Calculate risk score
            risk_score = self._calculate_risk_score(all_exposures)

            # Generate recommendations
            recommendations = self._generate_recommendations(all_exposures)

            return LLMScanResult(
                target=target,
                exposures=all_exposures,
                total_risk_score=risk_score,
                detected_technologies=list(detected_tech),
                recommendations=recommendations,
                scan_duration=time.time() - start_time
            )

        finally:
            if own_session:
                await session.close()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url.rstrip('/')

    def _calculate_risk_score(self, exposures: List[LLMExposure]) -> float:
        """Calculate aggregate risk score"""
        if not exposures:
            return 0.0

        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.5,
        }

        total = sum(severity_scores.get(e.severity, 0) for e in exposures)
        return min(total, 10.0)

    def _generate_recommendations(self, exposures: List[LLMExposure]) -> List[str]:
        """Generate consolidated recommendations"""
        recommendations = set()

        for exposure in exposures:
            recommendations.update(exposure.recommendations)

        # Add general recommendations
        if exposures:
            recommendations.add("Implement network segmentation for AI infrastructure")
            recommendations.add("Enable comprehensive logging for all AI/LLM endpoints")
            recommendations.add("Conduct regular security audits of AI deployments")

        return list(recommendations)

    def generate_report(self, result: LLMScanResult) -> str:
        """Generate human-readable report"""
        lines = [
            "=" * 70,
            "LLM/RAG INFRASTRUCTURE EXPOSURE SCAN",
            f"Target: {result.target}",
            f"Duration: {result.scan_duration:.2f}s",
            "=" * 70,
            "",
            f"Total Risk Score: {result.total_risk_score:.1f}/10.0",
            f"Total Exposures: {len(result.exposures)}",
            "",
        ]

        if result.detected_technologies:
            lines.append("DETECTED TECHNOLOGIES:")
            for tech in result.detected_technologies:
                lines.append(f"  🔍 {tech}")
            lines.append("")

        if result.exposures:
            # Group by severity
            by_severity = {}
            for exp in result.exposures:
                by_severity.setdefault(exp.severity, []).append(exp)

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                if severity in by_severity:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
                    lines.append(f"{emoji.get(severity.value, '⚪')} {severity.value.upper()} FINDINGS:")

                    for exp in by_severity[severity]:
                        lines.append(f"  • {exp.description}")
                        lines.append(f"    URL: {exp.url}")
                        if exp.evidence:
                            lines.append(f"    Evidence: {exp.evidence[0]}")
                        if exp.extracted_data:
                            lines.append(f"    Data: {json.dumps(exp.extracted_data)[:100]}...")
                    lines.append("")

        if result.recommendations:
            lines.append("RECOMMENDATIONS:")
            for rec in list(result.recommendations)[:10]:
                lines.append(f"  → {rec}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


async def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python llm_exposure_scanner.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = LLMExposureScanner()

    print(f"[*] Scanning {target} for LLM/RAG infrastructure exposure...")
    result = await scanner.scan(target)
    print(scanner.generate_report(result))


if __name__ == "__main__":
    asyncio.run(main())
