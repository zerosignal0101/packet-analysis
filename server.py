import asyncio
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List
import os
from multiprocessing import Process

import packet_analysis.preprocess.extract_to_csv as extract_to_csv

app = FastAPI()


class CollectPcap(BaseModel):
    collect_path: str
    ip: str
    prot: int


class ReplayPcap(BaseModel):
    replay_path: str
    ip: str
    prot: int
    replay_speed: str
    replay_multiplier: str


class PcapInfo(BaseModel):
    collect_pcap: List[CollectPcap]
    collect_log: str
    replay_pcap: ReplayPcap
    replay_log: str
    replay_task_id: int
    replay_id: str


class PcapInfoList(BaseModel):
    pcap_info: List[PcapInfo]


@app.post("/api/algorithm/analyze")
async def upload_pcap(request: Request):
    data = await request.json()
    pcap_info_list = PcapInfoList(**data)

    print(pcap_info_list.pcap_info[0].replay_pcap.replay_speed)

    # # 创建新的事件循环
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)

    if not os.path.exists('results'):
        os.makedirs('results')

    proc_list = []

    # 提取所有的 collect_path
    for index, pcap_info in enumerate(pcap_info_list.pcap_info):
        collect_paths = []
        for collect_pcap in pcap_info.collect_pcap:
            collect_paths.append(os.path.join("raw_data", collect_pcap.collect_path))
        print(collect_paths)
        # 生成 production_csv_file_path
        production_csv_file_path = f"results/extracted_production_data_{index}.csv"
        # 预处理数据
        # 调用 preprocess_data 函数处理生产环境的数据
        extract_to_csv.preprocess_data(collect_paths, production_csv_file_path)

        # 生成 replay_csv_file_path
        replay_csv_file_path = f"results/extracted_replay_data_{index}.csv"
        # 预处理数据
        # 调用 preprocess_data 函数处理回放环境的数据
        extract_to_csv.preprocess_data([pcap_info.replay_pcap.replay_path], replay_csv_file_path)

    return {"message": "Data received and processed", "data": pcap_info_list}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=7956)
