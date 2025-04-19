import os
from celery import group, chain, chord
import logging

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.pcap_splitter import split_pcap_file
# from src.packet_analysis.services.pcap_extractor import extract_info_from_pcap
from src.packet_analysis.utils.cache import get_file_hash, get_redis_client, CacheStatus

# Logger
logger = logging.getLogger(__name__)


def extract_pcap_info_with_chord(pcap_file, pair_id, side, options, use_cache=True):
    """
    Extracts information using splitting, parallel processing via chord, and caching.
    Waits for the chord to complete to return the final result.
    """
    redis_client = get_redis_client()
    if not redis_client or not redis_client._initialized:
        logger.warning(f"Redis not available for caching in extract_pcap_info for {pcap_file}.")
        use_cache = False
    file_hash = None
    cache_key = None
    # --- Cache Check ---
    if use_cache:
        try:
            file_hash = get_file_hash(pcap_file)
            cache_key = f"pcap_info:{file_hash}"
            if redis_client.check_status_exist(cache_key):
                logger.info(f"Cache status miss for {pcap_file} (hash: {file_hash}). Create status info with PENDING.")
                redis_client.set_status(cache_key, CacheStatus.CACHE_MISSING)
            else:
                logger.info(f"Cache status exist for {pcap_file} (hash: {file_hash}). Reusing it.")
            cache_status = redis_client.get_cache_status(cache_key)
            if cache_status == CacheStatus.CACHE_PENDING:
                logger.info(f"Cache already pending. No need to repeat the task scheduling for extraction.")
            elif (cache_status == CacheStatus.CACHE_READY or
                  cache_status == CacheStatus.READ_LOCKED or
                  cache_status == CacheStatus.WRITE_LOCKED):
                logger.info(f"Cache already in procession. No need to repeat the task scheduling for extraction.")
            elif cache_status == CacheStatus.CACHE_MISSING:
                logger.info(f"Cache missing. Create extraction workflow for {pcap_file} (hash: {file_hash}")
                redis_client.set_status(cache_key, CacheStatus.CACHE_PENDING)
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
            use_cache = False  # Disable cache for this run if check fails
    # --- Processing (Cache Miss or Cache Disabled) ---
    # Lock is held here by the decorator
    logger.info(f"Processing {pcap_file} (PairID: {pair_id}, Side: {side}). Lock acquired.")
    pcap_chunks = []  # Initialize chunk list
    try:
        # 1. Split the PCAP file
        # Ensure split_pcap_file returns a list of file paths to the chunks
        pcap_chunks = split_pcap_file(pcap_file, 100000)  # Example chunk size
        if not pcap_chunks:
            logger.warning(f"Splitting {pcap_file} resulted in no chunks.")
            return {"error": "No chunks generated", "file": pcap_file}, []
        logger.info(f"Split {pcap_file} into {len(pcap_chunks)} chunks.")
        # 2. Create signatures for the parallel chunk processing tasks (Chord Header)
        # Ensure extract_pcap_info_executor is defined as a Celery task
        executor_signatures = [extract_pcap_info_executor.s(chunk) for chunk in pcap_chunks]
        header = group(executor_signatures)
        # 3. Create signature for the finalization task (Chord Body/Callback)
        # Pass necessary context. Ensure file_hash and cache_key are calculated if not already.
        if use_cache and file_hash is None:  # Calculate hash if caching enabled but not done yet
            try:
                file_hash = get_file_hash(pcap_file)
                cache_key = f"pcap_info:{file_hash}"
            except Exception as e:
                logger.error(
                    f"Failed to get hash for caching result of {pcap_file}: {e}. Disabling cache for this run.")
                use_cache = False
                file_hash = None
                cache_key = None
        # Pass context needed by the callback
        callback = finalize_pcap_extraction.s(
            file_hash=file_hash if use_cache else None,  # Pass None if caching is disabled
            cache_key=cache_key if use_cache else None,
            pcap_chunks=pcap_chunks,  # Pass list of chunks for cleanup
            original_pcap_file=pcap_file  # Pass original filename for logging
        )
        # 4. Generate the chord and return the signature
        logger.info(f"Generate chord for {pcap_file}. Header: {len(executor_signatures)} tasks.")
        executor_chord = chord(header, callback)
        # 5. Options 返回在异常时需要清理的对象
        info_options = {
            "file_hash": file_hash,
            "pcap_chunks": pcap_chunks
        }
        if use_cache:
            info_options["cache_key"] = cache_key
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
        # Re-raise the exception for Celery's error handling (e.g., mark task as FAILED)
        # Or handle retries:
        # try:
        #     self.retry(exc=e, countdown=60, max_retries=2)
        # except MaxRetriesExceededError:
        #     logger.error(f"Max retries exceeded for {pcap_file}")
        #     return {"error": f"Processing failed after retries: {e}"}
        raise  # Re-raise the exception


def try_remove_chunk(chunk_path):
    """Safely attempts to remove a chunk file."""
    try:
        os.remove(chunk_path)
        logger.debug(f"Cleaned up chunk on error: {chunk_path}")
    except OSError as e:
        logger.error(f"Error cleaning up chunk {chunk_path} on error: {e}")


# Define the executor task TODO: (replace with your actual implementation)
@celery_app.task
def extract_pcap_info_executor(chunk_file):
    logger.info(f"Processing chunk: {chunk_file}")
    # Simulate work and return some result for the chunk
    import time
    time.sleep(1)
    result = {"chunk": chunk_file, "data": f"processed_data_{os.path.basename(chunk_file)}"}
    # Example: Clean up the chunk file immediately after processing
    # try:
    #     os.remove(chunk_file)
    #     logger.debug(f"Cleaned up chunk: {chunk_file}")
    # except OSError as e:
    #     logger.error(f"Error removing chunk file {chunk_file}: {e}")
    return result


@celery_app.task(bind=True)  # bind=True allows access to self for retries etc.
def finalize_pcap_extraction(self, results, file_hash, cache_key, pcap_chunks, original_pcap_file):
    """
    Callback task for the chord. Aggregates results, caches, and cleans up chunks.
    Receives the list of results from the executor tasks.
    """
    logger.info(f"Finalizing extraction for original file (hash: {file_hash}). Received {len(results)} results.")
    # 1. Aggregate results (if necessary)
    # 'results' is already a list of dictionaries from extract_pcap_info_executor
    # You might want to combine them into a single structure if needed.
    # For now, we'll assume the list itself is the desired final result.
    final_aggregated_result = results  # Or perform custom aggregation
    # 2. Cache the final result
    redis_client = get_redis_client()
    if redis_client and redis_client._initialized and file_hash and cache_key:
        try:
            # Potentially serialize 'final_aggregated_result' before storing
            logger.info(f"Storing aggregated result in cache key: {cache_key}")
            redis_client.set_cache(cache_key, final_aggregated_result, expire=3600)  # Cache for 1 hour
        except Exception as e:
            logger.exception(f"Failed to cache result for hash {file_hash} (key: {cache_key}): {e}")
            # Decide if failure to cache is critical. Maybe retry?
            # self.retry(exc=e, countdown=30, max_retries=2)
    # 3. Clean up chunk files (Important: Do this *after* processing/caching)
    #    Alternative: Chunks could be cleaned by the executor task itself right after processing.
    #    Cleaning here ensures all are attempted even if some executors failed, but might leave orphans if this task fails.
    logger.info(f"Cleaning up {len(pcap_chunks)} chunk files for {original_pcap_file}.")
    for chunk in pcap_chunks:
        try:
            os.remove(chunk)
            logger.debug(f"Cleaned up chunk: {chunk}")
        except FileNotFoundError:
            logger.warning(f"Chunk file not found for cleanup (already deleted?): {chunk}")
        except OSError as e:
            logger.error(f"Error removing chunk file {chunk}: {e}")
            # Log error but continue cleanup
    logger.info(f"Finalization complete for original file (hash: {file_hash}).")
    return final_aggregated_result  # This is the result the original caller will get
