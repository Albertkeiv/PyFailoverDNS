import pytest
from core.config_loader import load_config
from core.state import init_state, state

@pytest.fixture(scope="session", autouse=True)
def load_real_config():
    config = load_config("config.yaml")
    init_state(config)
    state["resolved"] = {}
    state["checks"] = {}