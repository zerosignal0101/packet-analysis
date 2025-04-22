import json
import time
import requests
import logging
from typing import List, Dict, Any, Optional

# Configure basic logging for demonstration purposes
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a reasonable timeout in seconds
DEFAULT_TIMEOUT = 10  # seconds


def send_callback_request(callback_url: str, result: Dict[str, Any]) -> Optional[requests.Response]:
    """
    Sends analysis results via an HTTP POST request to the specified callback URL.

    - Serializes result data as JSON for the HTTP request body.
    - Sets a timeout for the request.
    - Handles potential network/HTTP errors gracefully.
    - Logs success or failure information.
    - Authentication needs to be added if required (e.g., via headers or auth parameter).

    Args:
        callback_url: URL to send the callback to.
        result: Analysis results (Python dictionary) to be sent as JSON.

    Returns:
        requests.Response object if the request was successful (including 4xx/5xx status codes),
        or None if a connection error, timeout, or other request exception occurred before
        getting a response.
    """
    headers = {
        'Content-Type': 'application/json'
        # Add any necessary Authentication headers here, e.g.:
        # 'Authorization': 'Bearer YOUR_API_TOKEN'
        # 'X-API-Key': 'YOUR_API_KEY'
    }

    try:
        # Convert result dictionary to JSON string (requests does this automatically with 'json' parameter)
        # json_payload = json.dumps(result) # Manual serialization if needed

        logging.info(f"Sending callback POST request to: {callback_url}")

        response = requests.post(
            url=callback_url,
            json=result,  # Automatically serializes the dict to JSON and sets Content-Type
            headers=headers,
            timeout=DEFAULT_TIMEOUT
            # Add authentication if needed, e.g.:
            # auth=('username', 'password') # Basic Auth
        )

        # Optional: Raise an exception for bad status codes (4xx or 5xx)
        # If you want the function to return the response even for errors, comment this out.
        # If you want failures to raise exceptions here, uncomment it.
        # try:
        #     response.raise_for_status()
        #     logging.info(f"Callback request successful (Status code: {response.status_code})")
        # except requests.exceptions.HTTPError as http_err:
        #     logging.error(f"HTTP error occurred during callback: {http_err} - Status Code: {response.status_code}")
        #     # Depending on requirements, you might still return the response or return None/raise
        #     return response # Or return None

        # Log based on status code without raising exception immediately
        if 200 <= response.status_code < 300:
            logging.info(f"Callback request successful (Status code: {response.status_code})")
        else:
            logging.warning(f"Callback request completed but received non-success status: {response.status_code}")
            # Log response body for debugging if needed (be careful with sensitive data)
            # logging.debug(f"Callback response body: {response.text}")

        return response

    except requests.exceptions.Timeout as timeout_err:
        logging.error(f"Callback request timed out after {DEFAULT_TIMEOUT} seconds: {timeout_err}")
        return None
    except requests.exceptions.ConnectionError as conn_err:
        logging.error(f"Callback request connection error: {conn_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        # Catch any other request-related errors (e.g., Invalid URL)
        logging.error(f"An error occurred during the callback request: {req_err}")
        return None
    except Exception as e:
        # Catch any other unexpected errors (e.g., issues during logging itself)
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return None


# Example Usage (replace with actual URL and data)
if __name__ == '__main__':
    # Use a mock server like https://httpbin.org/post for testing
    test_callback_url = "https://httpbin.org/post"
    # test_callback_url_timeout = "https://httpbin.org/delay/15" # Test timeout
    # test_callback_url_error = "https://httpbin.org/status/500" # Test HTTP error
    # test_invalid_url = "invalid-url" # Test connection error

    test_result_data = {
        "analysis_id": "12345",
        "status": "completed",
        "timestamp": time.time(),
        "data": {
            "score": 0.85,
            "details": ["item1", "item2"]
        }
    }

    print("\n--- Testing Successful Callback ---")
    response = send_callback_request(test_callback_url, test_result_data)
    if response:
        print(f"Callback Response Status Code: {response.status_code}")
        try:
            print("Callback Response JSON:")
            print(response.json())  # Attempt to print response body as JSON
        except json.JSONDecodeError:
            print("Callback Response Body (non-JSON):")
            print(response.text)
    else:
        print("Callback request failed (returned None). Check logs for details.")

    # print("\n--- Testing Timeout ---")
    # response_timeout = send_callback_request(test_callback_url_timeout, test_result_data)
    # if response_timeout is None:
    #     print("Callback request correctly handled timeout (returned None).")
    # else:
    #      print(f"Callback timeout test unexpected response status: {response_timeout.status_code}")

    # print("\n--- Testing HTTP Error (500) ---")
    # response_error = send_callback_request(test_callback_url_error, test_result_data)
    # if response_error:
    #      print(f"Callback request correctly received HTTP error status: {response_error.status_code}")
    # else:
    #      print("Callback error test failed (returned None). Check logs.")

    # print("\n--- Testing Invalid URL ---")
    # response_invalid = send_callback_request(test_invalid_url, test_result_data)
    # if response_invalid is None:
    #     print("Callback request correctly handled invalid URL (returned None).")
    # else:
    #      print(f"Callback invalid URL test unexpected response status: {response_invalid.status_code}")
