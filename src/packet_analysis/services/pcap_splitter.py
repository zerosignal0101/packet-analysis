import os
import subprocess
import uuid
from pathlib import Path
import rootutils
import tempfile
import logging
from typing import List, Union  # Import List for type hinting

# project imports
from src.packet_analysis.utils.cache import get_file_hash
from src.packet_analysis.config import Config

# Logging
logger = logging.getLogger(__name__)


def split_pcap_file(pcap_file: Union[str, Path], max_packets_per_file: int) -> List[str]:
    """
    将单个 PCAP 文件分割成多个小文件，每个文件最多包含 max_packets_per_file 个包。
    使用 editcap 工具，并将输出文件放入带有基于输入文件内容哈希值的
    唯一名称的临时子目录中，以避免路径过长问题。

    Args:
        pcap_file: 输入的 PCAP 文件路径 (str or Path object)。
        max_packets_per_file: 每个分割文件包含的最大包数量。

    Returns:
        list: 分割后的文件绝对路径列表 (strings)。

    Raises:
        FileNotFoundError: If the input pcap_file does not exist or 'editcap' is not found.
        ValueError: If max_packets_per_file is not a positive integer.
        RuntimeError: If the editcap command fails or hashing fails.
    """
    pcap_file_path = Path(pcap_file).resolve()  # Ensure absolute path

    # --- Input Validation ---
    if not pcap_file_path.is_file():
        raise FileNotFoundError(f"Input PCAP file not found: {pcap_file_path}")
    if not isinstance(max_packets_per_file, int) or max_packets_per_file <= 0:
        raise ValueError("max_packets_per_file must be a positive integer.")

    # --- Calculate Input File Hash for Short Naming ---
    try:
        # Calculate MD5 hash of the input file content
        input_file_hash = get_file_hash(str(pcap_file_path))
        logger.info(f"Calculated MD5 hash for {pcap_file_path.name}: {input_file_hash}")
    except (FileNotFoundError, IOError) as e:
        # Error during hashing is critical, wrap and re-raise
        logger.error(f"Failed to calculate hash for {pcap_file_path}: {e}")
        raise RuntimeError(f"Hashing failed for input file: {pcap_file_path}") from e
    except Exception as e:  # Catch any other hashing errors
        logger.error(f"Unexpected error during hashing for {pcap_file_path}: {e}")
        raise RuntimeError(f"Unexpected hashing error for input file: {pcap_file_path}") from e

    # --- Prepare Output Directory and Filenames using Hash ---
    # Keep original suffix if needed later, but don't use it for globbing intermediate files
    # pcap_suffix = pcap_file_path.suffix
    random_id = uuid.uuid4().hex[:4]  # Short random hex ID for run uniqueness

    # Create a unique temporary directory using the file hash and a random ID
    # Format: base_temp_dir / file_hash_randomid
    output_dir = Path(os.path.join(Config.CHUNK_PCAP_STORAGE_DIR, f"{input_file_hash}_{random_id}"))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created temporary output directory: {output_dir}")
    except OSError as e:
        logger.error(f"Failed to create temporary directory {output_dir}: {e}")
        raise  # Re-raise the error

    # Define the base path pattern for output files using the hash
    # Format: output_dir / file_hash_chunk
    output_base_path = output_dir / f"{input_file_hash}_chunk"

    # --- Construct and Execute editcap Command ---
    command = [
        'editcap',
        '-c', str(max_packets_per_file),  # Split by packet count
        str(pcap_file_path),  # Input file
        str(output_base_path)  # Output file base path (using hash)
    ]

    logger.info(f"Executing command: {' '.join(command)}")  # Use logger

    try:
        # Execute the command
        result = subprocess.run(
            command,
            check=True,  # Raise CalledProcessError on non-zero exit code
            capture_output=True,  # Capture stdout/stderr
            text=True,  # Decode stdout/stderr as text
            encoding='utf-8'  # Explicitly set encoding
        )
        logger.info(f"editcap completed successfully.")  # Use logger
        logger.debug(f"editcap stdout:\n{result.stdout}")  # Use logger
        if result.stderr:  # Log stderr even on success
            logger.debug(f"editcap stderr:\n{result.stderr}")  # Use logger

    except FileNotFoundError:
        logger.error(
            "Error: 'editcap' command not found. Is Wireshark/TShark installed and in the system's PATH?")  # Use logger
        # Cleanup logic (optional, consider leaving dir on error for debugging)
        # ...
        raise  # Re-raise the original error

    except subprocess.CalledProcessError as e:
        logger.error(f"editcap command failed with return code {e.returncode}")  # Use logger
        logger.error(f"Command: {' '.join(e.cmd)}")  # Use logger
        logger.error(f"stdout:\n{e.stdout}")  # Use logger
        logger.error(f"stderr:\n{e.stderr}")  # Use logger
        # Cleanup logic (optional)
        # ...
        raise RuntimeError(f"editcap execution failed. Check logs for details.") from e

    # --- Find and Return Generated Files (Using Hash Prefix) ---
    # Search for files starting with the hashed base name, followed by '_' and anything.
    # Do NOT assume a specific suffix like .pcap, as editcap might omit it.
    glob_pattern = f"{output_base_path.name}_*"  # Match file_hash_chunk_*
    logger.debug(f"Searching for files in {output_dir} with pattern: {glob_pattern}")  # Use logger

    chunk_files_paths = sorted(list(output_dir.glob(glob_pattern)))

    # Handle case where the glob pattern didn't find anything
    if not chunk_files_paths:
        # Check if maybe editcap created *exactly* the base name (less likely when splitting)
        if output_base_path.is_file():
            logger.info(f"Found single output file matching base name: {output_base_path}")  # Use logger
            chunk_files_paths = [output_base_path]
        else:
            logger.warning(
                f"editcap ran successfully but no output files found matching pattern '{glob_pattern}' or the base name '{output_base_path.name}' in {output_dir}.")  # Use logger
            # You could list the directory content here for more debug info if needed:
            # existing_files = [str(f) for f in output_dir.glob('*')]
            # logger.warning(f"Actual files in dir: {existing_files}")
            return []  # Return empty list as specified

    # Convert Path objects to absolute path strings for the return list
    chunk_files_str = [str(f.resolve()) for f in chunk_files_paths]
    logger.info(f"Found {len(chunk_files_str)} split pcap file(s).")  # Use logger
    return chunk_files_str


# --- Example Usage (modified to show hash usage) ---
if __name__ == "__main__":
    # Configure logging for the example
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)  # Get logger for main block too

    # Create/find a test pcap file (same logic as before)
    test_pcap_filename = Path(tempfile.gettempdir()) / "test_large_file_for_hash.pcap"  # Different name
    # ... (rest of the dummy file creation logic from the previous example) ...
    # Make sure to handle the case where dummy creation fails and provide a real file path
    # For example:
    if not test_pcap_filename.exists():
        # *** Replace this line with the path to your actual large pcap file ***
        test_pcap_filename = Path(
            "./raw_data/raw_data_09622e39/1904462650620928001_1904473320196300802_1742896797.pcap")  # Example path
        if not test_pcap_filename.exists():
            logger.error(f"Test file not found: {test_pcap_filename}. Please provide a valid pcap file.")
            exit(1)
        else:
            logger.info(f"Using existing test file: {test_pcap_filename}")

    # --- Actual Splitting ---
    if test_pcap_filename and test_pcap_filename.exists():
        try:
            max_packets = 100000  # Or your desired size
            logger.info(
                f"\nSplitting '{test_pcap_filename}' into chunks of max {max_packets} packets using hash-based naming...")

            split_files = split_pcap_file(test_pcap_filename, max_packets)

            if split_files:
                logger.info("\nSplit files created:")
                temp_dir_used = Path(split_files[0]).parent  # Get the temp dir from one file
                logger.info(f"(Temporary files located in: {temp_dir_used})")
                for f in split_files:
                    logger.info(f" - {f}")

                # Optional: Clean up
                # import shutil
                # logger.info(f"\nCleaning up temporary directory: {temp_dir_used}")
                # try:
                #     shutil.rmtree(temp_dir_used)
                #     logger.info("Cleanup successful.")
                # except Exception as e_clean:
                #     logger.error(f"Error during cleanup: {e_clean}")
            else:
                logger.warning("\nNo split files were generated (check logs).")

        except (FileNotFoundError, ValueError, RuntimeError) as e:
            logger.error(f"\nError during splitting: {e}")
        except Exception as e_main:
            logger.error(f"\nAn unexpected error occurred: {e_main}", exc_info=True)  # Log traceback
        finally:
            # Clean up dummy file if created by this script run
            # ... (cleanup logic for test_large_file_for_hash.pcap) ...
            pass
    else:
        logger.warning(f"\nSkipping split test because input file '{test_pcap_filename}' does not exist.")
