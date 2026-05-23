#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║        AutonomSOC — Quick Start                      ║"
echo "║        Ghost Identity Hunter                         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────
command -v python3  >/dev/null || { echo "❌ python3 required"; exit 1; }
command -v docker   >/dev/null || { echo "❌ docker required";  exit 1; }
command -v ollama   >/dev/null || {
  echo "📦 Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
}

# ── Step 1: Start infrastructure ──────────────────────────────────────────────
echo "🐳 Step 1: Starting Docker services (Kafka, Neo4j, ChromaDB)..."
docker-compose up -d zookeeper kafka kafka-ui neo4j chromadb
echo "   Waiting 20s for services to be ready..."
sleep 20

# ── Step 2: Ollama models ────────────────────────────────────────────────────
echo ""
echo "🤖 Step 2: Pulling Ollama models..."
ollama serve &>/dev/null &
sleep 3
ollama pull llama3.1 && echo "   ✅ llama3.1"
ollama pull mistral  && echo "   ✅ mistral"

# ── Step 3: Python setup ─────────────────────────────────────────────────────
echo ""
echo "🐍 Step 3: Installing Python dependencies..."
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -q
echo "   ✅ Dependencies installed"

# ── Step 4: Generate synthetic data ──────────────────────────────────────────
echo ""
echo "📊 Step 4: Generating synthetic security events..."
cd ../data
python3 synthetic_generator.py --events 500 --attack all --output synthetic_logs.json
cd ../backend

# ── Step 5: Seed ChromaDB ────────────────────────────────────────────────────
echo ""
echo "🧠 Step 5: Seeding ChromaDB with MITRE ATT&CK knowledge base..."
python3 -c "from rag.chroma_store import setup_chroma; setup_chroma(); print('   ✅ ChromaDB seeded')"

# ── Step 6: Start backend API ────────────────────────────────────────────────
echo ""
echo "🚀 Step 6: Starting FastAPI backend..."
uvicorn api.routes:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!
sleep 4
curl -sf http://localhost:8000/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'   ✅ API running: {d[\"status\"]}')"

# ── Step 7: Start Kafka consumer ─────────────────────────────────────────────
echo ""
echo "📨 Step 7: Starting Kafka consumer (agent pipeline)..."
python3 -m kafka.consumer &
CONSUMER_PID=$!

# ── Step 8: Produce sample events ────────────────────────────────────────────
echo ""
echo "📤 Step 8: Producing sample events to Kafka..."
python3 -c "
from kafka.producer import create_producer, publish_raw_event, flush
import json

p = create_producer()
events = json.load(open('../data/synthetic_logs.json'))
anomalous = [e for e in events if e.get('is_anomaly')][:3]
for ev in anomalous:
    publish_raw_event(p, ev)
    print(f'   Sent: {ev.get(\"attack_type\",\"?\")} — {ev.get(\"identity_id\",\"?\")}')
flush(p)
print('   ✅ Sample events sent to Kafka')
"

# ── Step 9: Frontend ─────────────────────────────────────────────────────────
echo ""
echo "🎨 Step 9: Starting Next.js dashboard..."
cd ../frontend
if [ ! -d node_modules ]; then
  npm install --silent
fi
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev &>/dev/null &
FRONTEND_PID=$!

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅  AutonomSOC is running!                          ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  React Dashboard  → http://localhost:3000            ║"
echo "║  FastAPI Docs     → http://localhost:8000/docs       ║"
echo "║  Neo4j Browser    → http://localhost:7474            ║"
echo "║  Kafka UI         → http://localhost:8090            ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Neo4j creds: neo4j / autonomsoc2026                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop all services."

# Keep running until Ctrl+C
trap "kill $API_PID $CONSUMER_PID $FRONTEND_PID 2>/dev/null; docker-compose stop; echo 'Stopped.'" EXIT
wait
