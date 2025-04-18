# model/pcap_models.py
import os
from pydantic import BaseModel, validator, ValidationError
from typing import List, Optional


# --- Helper Function for File Validation ---
def check_file_exists(path: str, file_description: str) -> str:
    """Checks if a file exists at the given path. Raises ValueError if not."""
    if not os.path.isfile(path):
        raise ValueError(f"{file_description} not found at path: {path}")
    # You could add permission checks here too if needed:
    # if not os.access(path, os.R_OK):
    #     raise ValueError(f"Read permission denied for {file_description} at path: {path}")
    return path


# --- Pydantic Models with Validation ---

class ReplayPcap(BaseModel):
    replay_path: str
    ip: str
    port: int
    replay_speed: str
    replay_multiplier: str

    @validator('replay_path')
    def replay_path_must_exist(cls, v):
        return check_file_exists(v, "Replay PCAP file")


class CollectPcap(BaseModel):
    ip: str
    port: int
    collect_path: str

    @validator('collect_path')
    def collect_path_must_exist(cls, v):
        return check_file_exists(v, "Collect PCAP file")


class PcapInfo(BaseModel):
    replay_pcap: ReplayPcap  # Validation happens inside ReplayPcap
    collect_log: str
    collect_pcap: List[CollectPcap]  # Validation happens inside CollectPcap for each item
    replay_log: str
    replay_task_id: str
    replay_id: str

    @validator('collect_log')
    def pcapinfo_collect_log_must_exist(cls, v):
        # Assuming collect_log should be a JSON or similar file
        return check_file_exists(v, "PcapInfo Collect log file")

    @validator('replay_log')
    def pcapinfo_replay_log_must_exist(cls, v):
        # Assuming replay_log should be a JSON or similar file
        return check_file_exists(v, "PcapInfo Replay log file")


class AnalysisRequest(BaseModel):
    pcap_info: List[PcapInfo]  # Validation happens inside PcapInfo for each item
    collect_log: str
    replay_log: str
    replay_id: str
    replay_speed: str
    replay_multiplier: str

    @validator('collect_log')
    def analysis_collect_log_must_exist(cls, v):
        # Assuming collect_log should be a JSON or similar file
        return check_file_exists(v, "AnalysisRequest Collect log file")

    @validator('replay_log')
    def analysis_replay_log_must_exist(cls, v):
        # Assuming replay_log should be a JSON or similar file
        return check_file_exists(v, "AnalysisRequest Replay log file")
