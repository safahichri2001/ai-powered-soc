from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INJECAGENT_DIR = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "injecagent"
    / "InjecAgent"
    / "data"
)

ATTACKER_DH_FILE = INJECAGENT_DIR / "attacker_cases_dh.jsonl"
ATTACKER_DS_FILE = INJECAGENT_DIR / "attacker_cases_ds.jsonl"
USER_CASES_FILE = INJECAGENT_DIR / "user_cases.jsonl"

DH_BASE_FILE = INJECAGENT_DIR / "test_cases_dh_base.json"
DH_ENHANCED_FILE = INJECAGENT_DIR / "test_cases_dh_enhanced.json"

DS_BASE_FILE = INJECAGENT_DIR / "test_cases_ds_base.json"
DS_ENHANCED_FILE = INJECAGENT_DIR / "test_cases_ds_enhanced.json"

TOOLS_FILE = INJECAGENT_DIR / "tools.json"
RESPONSES_FILE = INJECAGENT_DIR / "attacker_simulated_responses.json"