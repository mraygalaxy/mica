#!/bin/bash
set -e

# Start Ollama server in background
ollama serve &
SERVER_PID=$!

# Wait for server to accept connections (ollama list exits 0 when server is up)
echo "Waiting for Ollama server..."
for i in $(seq 1 30); do
    if ollama list > /dev/null 2>&1; then
        echo "Ollama server is ready."
        break
    fi
    sleep 2
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Ollama server did not start in time."
        exit 1
    fi
done

# Pull model only if not already present (idempotent across restarts)
MODEL="qwen3:14b-q4_K_M"
if ollama list 2>/dev/null | grep -q "$MODEL"; then
    echo "Model $MODEL already present, skipping pull."
else
    echo "Pulling $MODEL (this will take a while on first run)..."
    ollama pull "$MODEL"
    echo "Model pull complete."
fi

echo "Ollama ready."
wait $SERVER_PID
