import os
from celery import group, chain, chord
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.pcap_splitter import split_pcap_file
from src.packet_analysis.services.pcap_extractor import process_pcap_to_parquet, PARQUET_COLUMNS
from src.packet_analysis.utils.cache import get_file_hash, get_redis_client, CacheStatus
from src.packet_analysis.config import Config

# Logger
logger = logging.getLogger(__name__)


def extract_pcap_info_with_chord(pcap_file, pair_id, side, options):
    """
    Extracts information using splitting, parallel processing via chord, and caching.
    Waits for the chord to complete to return the final result.
    Always uses caching by default.
    """
    redis_client = get_redis_client()
    if not redis_client or not redis_client._initialized:
        logger.warning(f"Redis not available for caching in extract_pcap_info for {pcap_file}.")
        return {"error": "Redis cache not available"}, {}

    file_hash = None
    cache_key = None
    pcap_chunks = []  # Initialize chunk list

    # --- Cache Check ---
    try:
        file_hash = get_file_hash(pcap_file)
        cache_key = f"pcap_info:{file_hash}"
        if redis_client.check_status_exist(cache_key):
            logger.info(f"Cache status exist for {pcap_file} (hash: {file_hash}). Reusing it.")
        else:
            logger.info(f"Cache status miss for {pcap_file} (hash: {file_hash}). Create status info with PENDING.")
            redis_client.set_cache_status(cache_key, CacheStatus.CACHE_MISSING)

        callback_cached = finalize_pcap_extraction.s(
            file_hash=file_hash,
            cache_key=cache_key,
            pcap_chunks=pcap_chunks,  # Pass list of chunks for cleanup
            original_pcap_file=pcap_file  # Pass original filename for logging
        )

        cache_status = redis_client.get_cache_status(cache_key)
        if cache_status == CacheStatus.CACHE_PENDING:
            logger.info(f"Cache already pending. No need to repeat the task scheduling for extraction.")
            return callback_cached, {}
        elif (cache_status == CacheStatus.CACHE_READY or
              cache_status == CacheStatus.READ_LOCKED or
              cache_status == CacheStatus.WRITE_LOCKED):
            logger.warning(f"Cache already in procession. Please check the status of {pcap_file}.")
            return callback_cached, {}
        elif cache_status == CacheStatus.CACHE_MISSING:
            logger.info(f"Cache missing. Create extraction workflow for {pcap_file} (hash: {file_hash}")
            redis_client.set_cache_status(cache_key, CacheStatus.CACHE_PENDING)
        else:
            raise ValueError(f"Invalid cache status for {pcap_file}")

    except FileNotFoundError:
        logger.error(f"File {pcap_file} not found during cache check. Task cannot proceed.")
        return {"error": f"File {pcap_file} not found during cache check"}, {}
    except IOError as e:
        logger.error(f"IOError accessing {pcap_file} during cache check: {e}")
        return {"error": f"IOError accessing {pcap_file} file during cache check: {e}"}, {}
    except Exception as e:
        logger.exception(f"Error during cache check for {pcap_file}: {e}")
        return {"error": f"Error during cache check: {e}"}, {}

    # --- Processing (Cache Miss or Cache Disabled) ---
    # Lock is held here by the decorator
    logger.info(f"Processing {pcap_file} (PairID: {pair_id}, Side: {side}). Lock acquired.")

    try:
        # 1. Split the PCAP file
        pcap_chunks = split_pcap_file(pcap_file, 100000)  # Example chunk size
        if not pcap_chunks:
            logger.warning(f"Splitting {pcap_file} resulted in no chunks.")
            return {"error": "No chunks generated", "file": pcap_file}, []

        logger.info(f"Split {pcap_file} into {len(pcap_chunks)} chunks.")

        # 2. Create signatures for the parallel chunk processing tasks (Chord Header)
        executor_signatures = [extract_pcap_info_executor.s(chunk) for chunk in pcap_chunks]
        header = group(executor_signatures)

        # 3. Create signature for the finalization task (Chord Body/Callback)
        callback = finalize_pcap_extraction.s(
            file_hash=file_hash,
            cache_key=cache_key,
            pcap_chunks=pcap_chunks,  # Pass list of chunks for cleanup
            original_pcap_file=pcap_file  # Pass original filename for logging
        )

        # 4. Generate the chord and return the signature
        logger.info(f"Generate chord for {pcap_file}. Header: {len(executor_signatures)} tasks.")
        executor_chord = chord(header, callback)

        # 5. Options 返回在异常时需要清理的对象
        info_options = {
            "file_hash": file_hash,
            "cache_key": cache_key,
            "pcap_chunks": pcap_chunks
        }

        return executor_chord, info_options

    except FileNotFoundError as e:
        logger.error(f"File {pcap_file} disappeared before processing. {e}")
        return {"error": f"File {pcap_file} disappeared during processing"}, {}
    except IOError as e:
        logger.error(f"IOError during processing of {pcap_file}: {e}")
        # Clean up any chunks created before the error
        for chunk in pcap_chunks: try_remove_chunk(chunk)
        return {"error": f"IOError during processing: {e}"}, {}
    except Exception as e:
        logger.exception(f"Error processing {pcap_file} within extract_pcap_info: {e}")
        # Clean up any potentially created chunks on failure
        logger.error(f"Cleaning up chunks for {pcap_file} due to error.")
        for chunk in pcap_chunks: try_remove_chunk(chunk)
        raise  # Re-raise the exception


def try_remove_chunk(chunk_path):
    """Safely attempts to remove a chunk file."""
    try:
        os.remove(chunk_path)
        logger.debug(f"Cleaned up chunk: {chunk_path}")
    except OSError as e:
        logger.error(f"Error cleaning up chunk {chunk_path} on error: {e}")


# Define the executor task TODO: (replace with your actual implementation)
@celery_app.task
def extract_pcap_info_executor(chunk_file):
    logger.info(f"Processing chunk: {chunk_file}")
    # 提取任务，带有 chunk 清理
    cache_key = process_pcap_to_parquet(chunk_file)
    result = {"chunk": chunk_file, "cache_key": cache_key}
    # 删除 chunk 文件
    try_remove_chunk(chunk_file)
    return result


@celery_app.task(bind=True)  # bind=True allows access to self for retries etc.
def finalize_pcap_extraction(self, results, file_hash, cache_key, pcap_chunks, original_pcap_file):
    """
    Callback task for the chord. Aggregates results, caches, and cleans up chunks.
    Receives the list of results from the executor tasks.
    """
    logger.info(f"Finalizing extraction for original pcap file (hash: {file_hash}). Received {len(results)} results.")
    redis_client = get_redis_client()
    # --- Caching Logic (similar to before) ---
    if not redis_client or not redis_client._initialized:
        logger.error("Redis client is not available. Cannot proceed with caching.")
        return None

    # 1. Aggregate results
    # (1). Initialize an empty list to store individual DataFrames
    dfs_to_concat = []
    # (2). Iterate through results, read Parquet files, and append to the list
    for entry in results:
        # chunk = entry["chunk"] # Use if needed for logging/context
        cache_key = entry["cache_key"]
        if redis_client.check_cache_exist(cache_key):
            chunk_parquet_file_path = redis_client.get_cache(cache_key)
            if chunk_parquet_file_path:
                try:
                    # Read the individual Parquet file into a temporary DataFrame
                    temp_df = pd.read_parquet(chunk_parquet_file_path, columns=PARQUET_COLUMNS)
                    # Append the temporary DataFrame to the list
                    dfs_to_concat.append(temp_df)
                    print(f"Successfully read and added: {chunk_parquet_file_path}")  # Optional logging
                except Exception as e:
                    # Handle potential errors during file reading (e.g., file not found, corrupted)
                    print(f"Error reading Parquet file {chunk_parquet_file_path} for key {cache_key}: {e}")
            else:
                print(f"Cache key {cache_key} exists but returned an empty path.")  # Optional logging
        else:
            print(f"Cache key {cache_key} not found in Redis.")  # Optional logging
    # (3). Concatenate all DataFrames in the list into the final result_df
    if dfs_to_concat:
        # Concatenate the list of DataFrames along rows (axis=0)
        # ignore_index=True creates a new continuous index for the resulting DataFrame
        result_df = pd.concat(dfs_to_concat, ignore_index=True, sort=False)
        print(f"Concatenated {len(dfs_to_concat)} DataFrames.")
    else:
        # If no valid Parquet files were found/read, create an empty DataFrame with the correct columns
        print("No Parquet files found or read. Creating an empty DataFrame.")
        result_df = pd.DataFrame(columns=PARQUET_COLUMNS)

    # Write parquet to file
    parquet_filename_base = file_hash if file_hash else os.path.splitext(os.path.basename(original_pcap_file))[0]
    result_parquet_file_path = os.path.join(Config.PARQUET_STORAGE_DIR, f"{parquet_filename_base}.parquet")
    os.makedirs(os.path.dirname(result_parquet_file_path), exist_ok=True)
    table = pa.Table.from_pandas(result_df, preserve_index=False)
    pq.write_table(table, result_parquet_file_path, compression='snappy')

    # 2. Cache the final result
    redis_client = get_redis_client()
    if redis_client and redis_client._initialized and file_hash and cache_key:
        try:
            # Potentially serialize 'final_aggregated_result' before storing
            logger.info(f"Storing aggregated result in cache key: {cache_key}")
            redis_client.set_cache(cache_key, result_parquet_file_path)
            redis_client.set_cache_status(cache_key, CacheStatus.CACHE_READY)
        except Exception as e:
            logger.exception(f"Failed to cache result for hash {file_hash} (key: {cache_key}): {e}")
            # Decide if failure to cache is critical. Maybe retry?
            # self.retry(exc=e, countdown=30, max_retries=2)
    # 3. Clean up chunk files (Important: Do this *after* processing/caching)
    #    Alternative: Chunks could be cleaned by the executor task itself right after processing.
    #    Cleaning here ensures all are attempted even if some executors failed, but might leave orphans if this task fails.
    for entry in results:
        cache_key = entry["cache_key"]
        if redis_client.check_cache_exist(cache_key):
            chunk_parquet_file_path = redis_client.get_cache(cache_key)
            if chunk_parquet_file_path:
                try_remove_chunk(chunk_parquet_file_path)
            redis_client.delete_cache(cache_key)
    logger.info(f"Finalization complete for original file (hash: {file_hash}).")
    return result_parquet_file_path  # This is the result the original caller will get
