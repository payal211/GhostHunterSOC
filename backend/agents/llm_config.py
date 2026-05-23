"""
AutonomSOC — LLM Configuration
Shared Ollama LLM factory used by all 6 agents.

Model routing strategy:
  mistral (4.1GB)  → Agents 1, 2, 5  (fast classification tasks)
  llama3.1 (4.7GB) → Agents 3, 4, 6  (reasoning, RAG, narrative)
  mixtral (26GB)   → Agent 4 optional (complex correlation, needs 32GB RAM)

To use Anthropic or OpenAI instead, swap get_llm() for the unified
mitre_llm_unified.py client — same prompt interface, different transport.
"""

import os
from langchain_ollama import OllamaLLM

OLLAMA_HOST  = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")

# Agent-to-model routing
AGENT_MODELS = {
    "identity_monitor":  os.getenv("MODEL_IDENTITY",  "mistral"),
    "behavior_analyzer": os.getenv("MODEL_BEHAVIOR",  "mistral"),
    "threat_intel":      os.getenv("MODEL_THREAT",    "llama3.1"),
    "correlation":       os.getenv("MODEL_CORRELATE", "llama3.1"),
    "response":          os.getenv("MODEL_RESPONSE",  "mistral"),
    "reporting":         os.getenv("MODEL_REPORT",    "llama3.1"),
}


def _normalize_ollama_model(model: str) -> str:
    if not model:
        return model
    return model if ":" in model else f"{model}:latest"


def get_llm(model: str = None, temperature: float = 0.1) -> OllamaLLM:
    """
    Returns an Ollama LLM instance.

    Args:
        model: Model name. If None, uses DEFAULT_MODEL from env.
               Options: llama3.1, llama3.2, mistral, mixtral, qwen2.5
        temperature: 0.1 for deterministic JSON output, 0.2 for narratives.

    Setup:
        ollama serve
        ollama pull llama3.1
        ollama pull mistral
    """
    normalized = _normalize_ollama_model(model or DEFAULT_MODEL)
    return OllamaLLM(
        model=normalized,
        temperature=temperature,
        base_url=OLLAMA_HOST,
        timeout=120,
    )


def get_agent_llm(agent_name: str, temperature: float = 0.1) -> OllamaLLM:
    """Returns the correct model for a specific agent."""
    model = AGENT_MODELS.get(agent_name, DEFAULT_MODEL)
    return get_llm(model=model, temperature=temperature)
