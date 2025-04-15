from datetime import datetime
import threading
import logging

log = logging.getLogger("STATE")

# Добавляем рекурсивный Lock
state_lock = threading.RLock()

state = {
    "config": None,
    "agents": {},
    "checks": {},
    "resolved": {}
}

def init_state(config):
    with state_lock:
        state["config"] = config

def atomic_state_update(callback):
    with state_lock:
        return callback(state)