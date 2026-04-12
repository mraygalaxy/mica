#!/bin/bash
set -e

# Refresh linker cache so libICTCLAS50.so (installed during build) is found at runtime
ldconfig

# Ensure required directories exist
mkdir -p /mica/logs /tmp/mica_scratch

# Sanity check: params.py must exist
if [ ! -f /mica/params.py ]; then
    echo ""
    echo "ERROR: params.py not found."
    echo "  cp /mica/params.py.template /mica/params.py"
    echo "  # then edit params.py to fill in your credentials"
    echo ""
    exit 1
fi

# Wait for CouchDB to be ready
echo "Waiting for CouchDB..."
for i in $(seq 1 30); do
    if curl -sf http://couchdb:5984/ > /dev/null 2>&1; then
        echo "CouchDB is up."
        break
    fi
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo "ERROR: CouchDB did not become ready in time."
        exit 1
    fi
done

# Wait for Ollama to be ready and the model to be pulled
echo "Waiting for Ollama model..."
for i in $(seq 1 60); do
    if curl -sf http://ollama:11434/api/tags 2>/dev/null | grep -q "qwen3:14b-q4_K_M"; then
        echo "Ollama model is ready."
        break
    fi
    sleep 5
    if [ "$i" -eq 60 ]; then
        echo "ERROR: Ollama did not become ready in time."
        exit 1
    fi
done

echo "Starting MICA..."
exec python2.7 /mica/test.py "$@"
