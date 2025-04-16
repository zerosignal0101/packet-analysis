# model/pcap_models.py
from pydantic import BaseModel
from typing import List, Optional

class ReplayPcap(BaseModel):
    replay_path: str
    ip: str
    port: int
    replay_speed: str
    replay_multiplier: str

class CollectPcap(BaseModel):
    ip: str
    port: int
    collect_path: str

class PcapInfo(BaseModel):
    replay_pcap: ReplayPcap
    collect_log: str
    collect_pcap: List[CollectPcap]
    replay_log: str
    replay_task_id: str
    replay_id: str

class AnalysisRequest(BaseModel):
    pcap_info: List[PcapInfo]
    collect_log: str
    replay_log: str
    replay_id: str
    replay_speed: str
    replay_multiplier: str
