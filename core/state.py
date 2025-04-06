from datetime import datetime
import logging

log = logging.getLogger("STATE")

state = {
    "config": None,
    "agents": {},
    "checks": {},  # {domain: {ip: {agent_id: {...}}}}
    "resolved": {}  # {domain: {"ip": str, "timestamp": datetime}}
}

def init_state(config):
    state["config"] = config