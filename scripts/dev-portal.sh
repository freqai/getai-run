#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${TMPDIR:-/tmp}/getai-run-8417.yaml"
BACKEND_LOG="${TMPDIR:-/tmp}/getai-run-8417.log"
FRONTEND_LOG="${TMPDIR:-/tmp}/getai-run-4173.log"
BACKEND_PORT=8417
FRONTEND_PORT=4173

cd "$ROOT"

show_help() {
    cat << EOF
Usage: $0 [command]

Commands:
  start     Start the development services (frontend & backend)
  stop      Stop all running services
  restart   Restart all services (stop then start)
  help      Show this help message

If no command is specified, 'start' is assumed.
EOF
}

stop_services() {
    echo "Stopping services..."
    
    # Stop backend on port $BACKEND_PORT
    if lsof -ti tcp:$BACKEND_PORT >/dev/null 2>&1; then
        lsof -ti tcp:$BACKEND_PORT | xargs kill 2>/dev/null || true
        echo "Stopped backend service on port $BACKEND_PORT"
    else
        echo "Backend service not running on port $BACKEND_PORT"
    fi
    
    # Stop frontend on port $FRONTEND_PORT
    if lsof -ti tcp:$FRONTEND_PORT >/dev/null 2>&1; then
        lsof -ti tcp:$FRONTEND_PORT | xargs kill 2>/dev/null || true
        echo "Stopped frontend service on port $FRONTEND_PORT"
    else
        echo "Frontend service not running on port $FRONTEND_PORT"
    fi
    
    echo "All services stopped."
}

start_services() {
    echo "Starting services..."
    
    # Copy config and modify port
    cp config.example.yaml "$CONFIG_PATH"
    perl -0pi -e 's/port: 8317/port: 8417/' "$CONFIG_PATH"
    
    # Stop any existing backend processes
    if lsof -ti tcp:$BACKEND_PORT >/dev/null 2>&1; then
        lsof -ti tcp:$BACKEND_PORT | xargs kill
    fi
    
    # Start frontend if not running
    if ! lsof -ti tcp:$FRONTEND_PORT >/dev/null 2>&1; then
        nohup python3 -m http.server $FRONTEND_PORT --directory website >"$FRONTEND_LOG" 2>&1 &
        echo "Frontend service started on port $FRONTEND_PORT"
    else
        echo "Frontend service already running on port $FRONTEND_PORT"
    fi
    
    # Prepare environment variables
    export_env=""
    if [ -n "${PGSTORE_DSN:-}" ]; then
        export_env="PGSTORE_DSN=$PGSTORE_DSN"
    fi
    if [ -n "${USAGE_PG_DSN:-}" ]; then
        export_env="${export_env} USAGE_PG_DSN=$USAGE_PG_DSN"
    fi
    if [ -n "${PGSTORE_SCHEMA:-}" ]; then
        export_env="${export_env} PGSTORE_SCHEMA=$PGSTORE_SCHEMA"
    fi
    if [ -n "${USAGE_PG_SCHEMA:-}" ]; then
        export_env="${export_env} USAGE_PG_SCHEMA=$USAGE_PG_SCHEMA"
    fi
    
    # Start backend
    if [ -n "$export_env" ]; then
        echo "Using PostgreSQL environment variables: $export_env"
        eval "nohup env $export_env go run ./cmd/server --config \"$CONFIG_PATH\" --no-browser >\"$BACKEND_LOG\" 2>&1 &"
    else
        nohup go run ./cmd/server --config "$CONFIG_PATH" --no-browser >"$BACKEND_LOG" 2>&1 &
    fi
    
    echo "Backend service starting on port $BACKEND_PORT"
    
    # Wait a moment for services to start
    sleep 2
    
    echo ""
    echo "Services started successfully!"
    echo "Frontend: http://127.0.0.1:$FRONTEND_PORT/"
    echo "Backend:  http://127.0.0.1:$BACKEND_PORT/"
    echo "Logs:"
    echo "  $FRONTEND_LOG"
    echo "  $BACKEND_LOG"
}

# Parse command line arguments
case "${1:-start}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        echo ""
        start_services
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac