#!/bin/bash
# ==============================================================================
# Typosquat & Brand Impersonation Threat Intelligence Platform
# Master Turnkey Execution Script (Final Year Project)
# ==============================================================================

set -e

# Detect virtual environment
if [ -d ".venv" ]; then
    PYTHON=".venv/bin/python"
    STREAMLIT=".venv/bin/streamlit"
    PYTEST=".venv/bin/pytest"
    UVICORN=".venv/bin/uvicorn"
else
    PYTHON="python3"
    STREAMLIT="streamlit"
    PYTEST="pytest"
    UVICORN="uvicorn"
fi

print_header() {
    echo "=============================================================================="
    echo " 🛡️  TYPOSQUAT & BRAND IMPERSONATION THREAT INTELLIGENCE PLATFORM"
    echo "     Autonomous Detection, Multi-Vector Enrichment & Takedown Engine"
    echo "=============================================================================="
}

show_menu() {
    print_header
    echo "Select an option to launch:"
    echo "  [1] Launch SOC Streamlit Dashboard (http://localhost:8501)"
    echo "  [2] Launch FastAPI REST Backend (http://localhost:8000/docs)"
    echo "  [3] Run Certificate Transparency (CT) Stream Simulator (Live Presentation Demo)"
    echo "  [4] Run High-Risk Threat Pipeline Demo & Generate Legal Takedown PDF"
    echo "  [5] Seed Database with Realistic Multi-Brand Threat Data"
    echo "  [6] Run Live CT Stream Ingestion Worker (WebSocket Ingestion)"
    echo "  [7] Run Automated Pytest Test Suite"
    echo "  [8] Exit"
    echo "------------------------------------------------------------------------------"
    read -p "Enter choice [1-8]: " choice

    case $choice in
        1)
            echo "Starting SOC Dashboard on http://localhost:8501..."
            $STREAMLIT run dashboard/app.py --server.port=8501
            ;;
        2)
            echo "Starting FastAPI REST API on http://localhost:8000..."
            echo "Interactive Swagger Docs: http://localhost:8000/docs"
            $UVICORN src.api.main:app --host 0.0.0.0 --port 8000 --reload
            ;;
        3)
            echo "Launching Live CT Stream Simulator..."
            $PYTHON -m src.ingest.ct_simulator
            ;;
        4)
            echo "Running High-Risk Threat Simulation & Dossier Generation..."
            $PYTHON demo_high_risk_trigger.py
            ;;
        5)
            echo "Populating SQLite Database with Threat Telemetry..."
            $PYTHON seed_data.py
            ;;
        6)
            echo "Connecting to Certificate Transparency Stream Worker..."
            $PYTHON -m src.ingest.ct_stream_client
            ;;
        7)
            echo "Executing Pytest Test Suite..."
            $PYTEST tests/ -v
            ;;
        8)
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please run again."
            exit 1
            ;;
    esac
}

# If CLI arguments are provided, handle them directly
if [ "$1" == "dashboard" ]; then
    $STREAMLIT run dashboard/app.py --server.port=8501
elif [ "$1" == "api" ]; then
    $UVICORN src.api.main:app --host 0.0.0.0 --port 8000
elif [ "$1" == "simulate" ]; then
    $PYTHON -m src.ingest.ct_simulator
elif [ "$1" == "demo" ]; then
    $PYTHON demo_high_risk_trigger.py
elif [ "$1" == "seed" ]; then
    $PYTHON seed_data.py
elif [ "$1" == "test" ]; then
    $PYTEST tests/ -v
else
    show_menu
fi
