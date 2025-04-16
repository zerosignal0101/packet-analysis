from scapy.utils import PcapReader, PcapWriter
import os
from pathlib import Path


def split_pcap_file(pcap_file, max_size):
    """将单个 PCAP 文件分割成多个小文件，每个文件最多包含 max_size 个包

    Args:
        pcap_file: 输入的 PCAP 文件路径
        max_size: 每个分割文件包含的最大包数量

    Returns:
        list: 分割后的文件路径列表
    """
    chunk_files = []
    base_name = Path(pcap_file).stem
    output_dir = Path(pcap_file).parent

    with PcapReader(pcap_file) as pcap_reader:
        packet_count = 0
        chunk_count = 1
        current_writer = None

        for packet in pcap_reader:
            # 如果是第一个包或者达到最大包数，创建新的写入器
            if packet_count % max_size == 0:
                if current_writer is not None:
                    current_writer.close()

                chunk_filename = f"{base_name}_part{chunk_count}.pcap"
                chunk_path = output_dir / chunk_filename
                current_writer = PcapWriter(str(chunk_path))
                chunk_files.append(str(chunk_path))
                chunk_count += 1

            # 写入当前包
            current_writer.write(packet)
            packet_count += 1

        # 关闭最后一个写入器
        if current_writer is not None:
            current_writer.close()

    return chunk_files
