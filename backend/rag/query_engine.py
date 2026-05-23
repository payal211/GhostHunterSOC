"""LlamaIndex RAG Query Engine — Wraps ChromaDB with LlamaIndex for enhanced retrieval."""

import os
from llama_index.core import VectorStoreIndex, Document, Settings
from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.llms.ollama import Ollama
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
import chromadb


def create_rag_engine(persist_dir: str = "./chroma_db"):
    """Creates a LlamaIndex RAG query engine backed by ChromaDB."""
    # Configure LLM
    llm = Ollama(
        model=os.getenv("OLLAMA_MODEL", "llama3.1"),
        base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        request_timeout=120,
    )
    Settings.llm = llm

    # Use local embeddings
    embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")
    Settings.embed_model = embed_model

    # Connect to ChromaDB
    client = chromadb.PersistentClient(path=persist_dir)
    try:
        chroma_collection = client.get_collection("mitre_threat_intel")
    except Exception:
        from rag.chroma_store import setup_chroma
        chroma_collection = setup_chroma(persist_dir)

    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    index = VectorStoreIndex.from_vector_store(vector_store)
    query_engine = index.as_query_engine(similarity_top_k=3)

    return query_engine


def query_rag(query_engine, question: str) -> str:
    """Queries the RAG engine and returns the response."""
    response = query_engine.query(question)
    return str(response)