#!/bin/bash
# =============================================================
# 文件上传服务一键启动脚本
#
# 用法:
#   ./start.sh              启动服务（默认目录 /file，端口 8000）
#   ./start.sh stop         停止服务
#   ./start.sh restart      重启服务
#   ./start.sh status       查看运行状态
#
# 可用环境变量覆盖默认配置:
#   UPLOAD_DIR=/data/files  上传目录（默认 /file）
#   UPLOAD_PORT=8000        监听端口（默认 8000）
#   UPLOAD_HOST=0.0.0.0     监听地址（默认 0.0.0.0）
#   UPLOAD_CHUNK_MB=8       分片大小 MB（默认 8）
#
# 示例: UPLOAD_DIR=/data/files UPLOAD_PORT=9000 ./start.sh
# =============================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_FILE="$SCRIPT_DIR/upload_server.py"
PID_FILE="$SCRIPT_DIR/upload_server.pid"
LOG_FILE="$SCRIPT_DIR/upload_server.log"

UPLOAD_DIR="${UPLOAD_DIR:-/file}"
UPLOAD_PORT="${UPLOAD_PORT:-8000}"
UPLOAD_HOST="${UPLOAD_HOST:-0.0.0.0}"
UPLOAD_CHUNK_MB="${UPLOAD_CHUNK_MB:-8}"

# ---------- 选择 Python 解释器（优先 Python 2.7）----------
find_python() {
    for cmd in python2.7 python2 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if "$cmd" -c 'import sys; sys.exit(0 if sys.version_info[0] == 2 else 1)' 2>/dev/null; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    # 没有 Python 2 时退回 python3（代码兼容，可用于测试）
    if command -v python3 >/dev/null 2>&1; then
        echo "python3"
        return 0
    fi
    return 1
}

PYTHON="$(find_python)" || { echo "[错误] 未找到可用的 Python 解释器"; exit 1; }

get_pid() {
    awk -F: '{print $1}' "$PID_FILE" 2>/dev/null
}

get_port() {
    awk -F: '{print $2}' "$PID_FILE" 2>/dev/null
}

is_running() {
    local pid; pid="$(get_pid)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

do_start() {
    if is_running; then
        local port; port="$(get_port)"
        echo "[提示] 服务已在运行 (PID $(get_pid), 端口 ${port:-$UPLOAD_PORT})"
        exit 0
    fi

    # 端口被其他程序占用时提前报错，避免启动后无法访问
    if command -v ss >/dev/null 2>&1; then
        if ss -tln 2>/dev/null | grep -q ":$UPLOAD_PORT "; then
            echo "[错误] 端口 $UPLOAD_PORT 已被其他程序占用，请换端口:"
            echo "       UPLOAD_PORT=8010 ./start.sh"
            exit 1
        fi
    fi

    [ -f "$PID_FILE" ] && rm -f "$PID_FILE"

    echo "[启动] $PYTHON upload_server.py --dir $UPLOAD_DIR --port $UPLOAD_PORT"
    nohup "$PYTHON" "$SERVER_FILE" \
        --dir "$UPLOAD_DIR" --port "$UPLOAD_PORT" \
        --host "$UPLOAD_HOST" --chunk-size "$UPLOAD_CHUNK_MB" \
        >> "$LOG_FILE" 2>&1 &

    echo $!:$UPLOAD_PORT > "$PID_FILE"
    sleep 1

    if ! is_running; then
        echo "[错误] 服务启动失败，最近日志:"
        tail -5 "$LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi

    echo "[完成] 服务已启动 (PID $(get_pid))"
    echo "  访问地址 : http://本机IP:$UPLOAD_PORT/"
    echo "  保存目录 : $UPLOAD_DIR"
    echo "  日志文件 : $LOG_FILE"
    echo "  停止服务 : ./start.sh stop"
}

do_stop() {
    if ! is_running; then
        echo "[提示] 服务未在运行"
        [ -f "$PID_FILE" ] && rm -f "$PID_FILE"
        exit 0
    fi
    local pid; pid="$(get_pid)"
    echo "[停止] PID $pid"
    kill "$pid" 2>/dev/null
    for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    rm -f "$PID_FILE"
    echo "[完成] 服务已停止"
}

do_status() {
    if is_running; then
        local port; port="$(get_port)"
        echo "[状态] 运行中 (PID $(get_pid), 端口 ${port:-$UPLOAD_PORT})"
    else
        echo "[状态] 未运行"
    fi
}

case "${1:-start}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; do_start ;;
    status)  do_status ;;
    *) echo "用法: $0 [start|stop|restart|status]"; exit 1 ;;
esac
