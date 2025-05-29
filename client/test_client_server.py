"""
Test script for client-server interactions.

This script provides basic integration tests for the SCREENSHOT_MODE and 
ENCRYPT_MODE functionalities of the client-server application.
It requires the server to be running separately on the configured SERVER_ADDRESS and PORT.

Usage:
    Run from the root directory of the project (e.g., where 'client' and 'server' folders are):
    python client/test_client_server.py

    Ensure the C server (`./server/server_app` or similar) is compiled and running 
    before executing these tests.
"""
import socket
import os
import struct
import time # For potential delays or specific timeout tests if added later

# Assuming client.protocol is in the same directory or PYTHONPATH is set up
try:
    from protocol import (
        PacketModes, AckPacket, # ProtocolPacket class is not directly used by test logic here
        initialize_communication, close_communication,
        set_packet, send_packet, # serialize_packet is used internally by send_packet
        get_file, send_file_to_encrypt, 
        handle_acknowledgment, calculate_crc32,
        MAGIC_NUMBER, HEADER_FORMAT, HEADER_SIZE, SERVER_ADDRESS, PORT
        # DEFAULT_SCREENSHOT_FILE_NAME from protocol.py is not used here;
        # this test script uses its own constants for test filenames.
    )
except ImportError as e:
    print(f"ImportError: {e} - Could not import from 'protocol'.")
    print("Ensure this script is in the 'client' directory, or that the 'client' directory")
    print("is correctly added to your PYTHONPATH if running from elsewhere.")
    print("Example: If in project root, run as 'python client/test_client_server.py'")
    exit(1)

# Test-specific filenames to avoid conflict with actual client output files
CLIENT_TEST_SCREENSHOT_FILENAME = "test_client_screenshot.jpg"
CLIENT_TEST_ENCRYPT_INPUT_FILENAME = "test_client_to_encrypt.txt"
CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME = "test_client_encrypted_output.enc"

def setup_test_environment():
    """
    Prepares the test environment by removing any artifact files from previous test runs.
    This ensures tests start with a clean state.
    """
    print("Setting up test environment (cleaning previous test files)...")
    for f_path in [CLIENT_TEST_SCREENSHOT_FILENAME, CLIENT_TEST_ENCRYPT_INPUT_FILENAME, CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME]:
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
                print(f"  Removed pre-existing test file: {f_path}")
            except OSError as e:
                print(f"  Warning: Could not remove pre-existing file {f_path}: {e}")

def cleanup_test_environment():
    """
    Cleans up files created during the execution of the tests.
    This is important for maintaining a clean state for subsequent test runs.
    """
    print("\nCleaning up test environment (removing generated test files)...")
    for f_path in [CLIENT_TEST_SCREENSHOT_FILENAME, CLIENT_TEST_ENCRYPT_INPUT_FILENAME, CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME]:
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
                print(f"  Removed test file: {f_path}")
            except Exception as e:
                print(f"  Error removing test file {f_path}: {e}")
        else:
            print(f"  Test file not found (already cleaned or never created): {f_path}")


def test_screenshot_mode() -> bool:
    """
    Tests the SCREENSHOT_MODE functionality from client to server.
    
    Steps:
    1. Connects to the server.
    2. Sends a SCREENSHOT_MODE request packet.
    3. Receives and validates the FILE_SIZE_MODE packet (header and payload) from the server.
    4. Extracts the expected screenshot file size.
    5. Sends an ACK_MODE packet to the server acknowledging receipt of the file size.
    6. Calls the `get_file` function to download the screenshot data.
    7. Verifies that the downloaded file exists and its size matches the expected size.
    8. Optionally checks for JPEG magic bytes in the downloaded file.
    
    Returns:
        True if all steps are completed successfully and verifications pass, False otherwise.
    """
    print("\n--- Testing SCREENSHOT_MODE ---")
    client_socket = initialize_communication(PORT, SERVER_ADDRESS)
    if not client_socket:
        print("TEST FAILED: Could not connect to server for screenshot test.")
        return False

    success = False
    try:
        print("Sending SCREENSHOT_MODE request...")
        # Create initial SCREENSHOT_MODE packet (no payload, checksum 0)
        # set_packet now calculates checksum internally. For no payload, it's 0.
        screenshot_request_packet = set_packet(PacketModes.SCREENSHOT_MODE)
        if not screenshot_request_packet:
            print("TEST FAILED: Could not create screenshot_request_packet.")
            return False
        
        if not send_packet(client_socket, screenshot_request_packet):
            print("TEST FAILED: Could not send screenshot_request_packet.")
            return False

        print("Waiting for FILE_SIZE_MODE from server...")
        # Receive FILE_SIZE_MODE packet header
        fsm_header_data = client_socket.recv(HEADER_SIZE)
        if not fsm_header_data or len(fsm_header_data) != HEADER_SIZE:
            print(f"TEST FAILED: Did not receive complete FILE_SIZE_MODE header. Got: {len(fsm_header_data) if fsm_header_data else 0} bytes.")
            return False

        fsm_magic, fsm_mode, fsm_payload_len, fsm_checksum = struct.unpack(HEADER_FORMAT, fsm_header_data)

        if fsm_magic != MAGIC_NUMBER:
            print(f"TEST FAILED: Invalid magic number in FILE_SIZE_MODE. Got: {fsm_magic}")
            return False
        if fsm_mode != PacketModes.FILE_SIZE_MODE.value:
            print(f"TEST FAILED: Unexpected mode. Expected FILE_SIZE_MODE ({PacketModes.FILE_SIZE_MODE.value}), Got: {fsm_mode}")
            return False
        if fsm_payload_len != 8: # Expecting uint64_t for file size
            print(f"TEST FAILED: Unexpected payload length for FILE_SIZE_MODE. Expected 8, Got: {fsm_payload_len}")
            return False
        
        print(f"FILE_SIZE_MODE header received: Mode={fsm_mode}, PayloadLen={fsm_payload_len}, Checksum={fsm_checksum}")

        # Receive FILE_SIZE_MODE payload
        fsm_payload_data = client_socket.recv(fsm_payload_len)
        if not fsm_payload_data or len(fsm_payload_data) != fsm_payload_len:
            print("TEST FAILED: Did not receive complete FILE_SIZE_MODE payload.")
            return False

        if calculate_crc32(fsm_payload_data) != fsm_checksum:
            print(f"TEST FAILED: FILE_SIZE_MODE checksum mismatch. Expected {fsm_checksum}, Got {calculate_crc32(fsm_payload_data)}")
            return False
        
        screenshot_file_size = struct.unpack("!Q", fsm_payload_data)[0]
        print(f"Received screenshot file size: {screenshot_file_size} bytes.")

        # Send ACK for FILE_SIZE_MODE
        print("Sending ACK for FILE_SIZE_MODE...")
        if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.SEND_ACK_PACKET):
            print("TEST FAILED: Failed to send ACK for FILE_SIZE_MODE.")
            return False

        # Receive the actual screenshot file
        print(f"Receiving screenshot file ({CLIENT_TEST_SCREENSHOT_FILENAME})...")
        if os.path.exists(CLIENT_TEST_SCREENSHOT_FILENAME): # Clean up if exists from previous failed run
            os.remove(CLIENT_TEST_SCREENSHOT_FILENAME)

        if not get_file(client_socket, CLIENT_TEST_SCREENSHOT_FILENAME, screenshot_file_size):
            print("TEST FAILED: get_file for screenshot failed.")
            return False
        
        # Verification
        if os.path.exists(CLIENT_TEST_SCREENSHOT_FILENAME) and os.path.getsize(CLIENT_TEST_SCREENSHOT_FILENAME) == screenshot_file_size:
            print(f"SUCCESS: Screenshot received and saved as {CLIENT_TEST_SCREENSHOT_FILENAME}, size {os.path.getsize(CLIENT_TEST_SCREENSHOT_FILENAME)} matches expected {screenshot_file_size}.")
            # Optional: Check JPEG magic bytes
            with open(CLIENT_TEST_SCREENSHOT_FILENAME, 'rb') as f:
                magic_bytes = f.read(3)
                if magic_bytes == b'\xFF\xD8\xFF':
                    print("  JPEG magic bytes check: PASSED")
                else:
                    print(f"  JPEG magic bytes check: FAILED (Got: {magic_bytes.hex()})")
            success = True
        else:
            print(f"TEST FAILED: Screenshot file verification failed. Exists: {os.path.exists(CLIENT_TEST_SCREENSHOT_FILENAME)}, Size: {os.path.getsize(CLIENT_TEST_SCREENSHOT_FILENAME) if os.path.exists(CLIENT_TEST_SCREENSHOT_FILENAME) else 'N/A'}")

    except socket.timeout:
        print("TEST FAILED: Socket timeout during screenshot test.")
    except ConnectionRefusedError:
        print("TEST FAILED: Connection refused. Server might not be running.")
    except Exception as e:
        print(f"TEST FAILED: An error occurred during screenshot test: {e}")
    finally:
        if client_socket:
            close_communication(client_socket)
    return success

def test_encrypt_mode() -> bool:
    """
    Tests the ENCRYPT_MODE functionality from client to server.

    Steps:
    1. Creates a sample input file with known content.
    2. Connects to the server.
    3. Sends an initial ENCRYPT_MODE request packet (containing the original file's size).
    4. Calls `send_file_to_encrypt` to upload the content of the sample file.
    5. Receives and validates the FILE_SIZE_MODE packet for the (now encrypted) file from the server.
    6. Extracts the expected encrypted file size.
    7. Sends an ACK_MODE packet to the server acknowledging receipt of the encrypted file size.
    8. Calls `get_file` to download the encrypted file data.
    9. Verifies that the downloaded encrypted file exists and its size matches.
    
    Note: This test does not attempt to decrypt the file, only verifies the protocol flow
    and data transfer integrity based on reported sizes and checksums.
    
    Returns:
        True if all steps are completed successfully and verifications pass, False otherwise.
    """
    print("\n--- Testing ENCRYPT_MODE ---")
    # 1. Create a dummy file with sample content to be encrypted.
    # Using a larger, more varied content can be beneficial for thorough testing.
    sample_content = (b"This is a test string for the encryption test. "
                      b"It includes various characters like 12345 and !@#$%^&*().\n"
                      b"Repetition helps to create a reasonably sized file for transfer. ") * 50
    try:
        with open(CLIENT_TEST_ENCRYPT_INPUT_FILENAME, "wb") as f:
            f.write(sample_content)
        print(f"  Created dummy file for encryption: {CLIENT_TEST_ENCRYPT_INPUT_FILENAME} (Size: {len(sample_content)} bytes)")
    except IOError as e:
        print(f"TEST FAILED: Could not create dummy file '{CLIENT_TEST_ENCRYPT_INPUT_FILENAME}': {e}")
        return False

    client_socket = initialize_communication(PORT, SERVER_ADDRESS)
    if not client_socket:
        print("TEST FAILED: Could not connect to server for encryption test.")
        return False

    success = False
    try:
        print("Sending ENCRYPT_MODE request...")
        original_file_size = os.path.getsize(TEST_ENCRYPT_INPUT_FILENAME)
        payload_data = struct.pack("!Q", original_file_size) # 8-byte unsigned long long

        # set_packet calculates checksum internally
        encrypt_request_packet = set_packet(PacketModes.ENCRYPT_MODE, payload_data)
        if not encrypt_request_packet:
            print("TEST FAILED: Could not create encrypt_request_packet.")
            return False
        
        if not send_packet(client_socket, encrypt_request_packet):
            print("TEST FAILED: Could not send encrypt_request_packet.")
            return False
        
        print(f"Sent ENCRYPT_MODE request with original file size: {original_file_size}")

        # Send the actual file to be encrypted
        print(f"Sending file content of {CLIENT_TEST_ENCRYPT_INPUT_FILENAME}...")
        if not send_file_to_encrypt(client_socket, CLIENT_TEST_ENCRYPT_INPUT_FILENAME):
            print("TEST FAILED: send_file_to_encrypt failed.")
            return False
        
        # After successfully sending the file, wait for server to send FILE_SIZE_MODE for the encrypted file
        print("File content sent. Waiting for FILE_SIZE_MODE (for encrypted file) from server...")
        # Receive FILE_SIZE_MODE packet for the encrypted file
        efs_header_data = client_socket.recv(HEADER_SIZE)
        if not efs_header_data or len(efs_header_data) != HEADER_SIZE:
            print("TEST FAILED: Did not receive complete FILE_SIZE_MODE header for encrypted file.")
            return False

        efs_magic, efs_mode, efs_payload_len, efs_checksum = struct.unpack(HEADER_FORMAT, efs_header_data)

        if efs_magic != MAGIC_NUMBER or efs_mode != PacketModes.FILE_SIZE_MODE.value:
            print("TEST FAILED: Invalid FILE_SIZE_MODE packet for encrypted file (header).")
            return False
        if efs_payload_len != 8:
            print(f"TEST FAILED: Unexpected payload length for encrypted FILE_SIZE_MODE. Expected 8, Got: {efs_payload_len}")
            return False
        
        efs_payload_data = client_socket.recv(efs_payload_len)
        if not efs_payload_data or len(efs_payload_data) != efs_payload_len:
            print("TEST FAILED: Did not receive complete FILE_SIZE_MODE payload for encrypted file.")
            return False

        if calculate_crc32(efs_payload_data) != efs_checksum:
            print("TEST FAILED: Encrypted FILE_SIZE_MODE checksum mismatch.")
            return False
            
        encrypted_file_size = struct.unpack("!Q", efs_payload_data)[0]
        print(f"Received encrypted file size: {encrypted_file_size} bytes.")

        # Send ACK for FILE_SIZE_MODE
        print("Sending ACK for encrypted file's FILE_SIZE_MODE...")
        if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.SEND_ACK_PACKET):
            print("TEST FAILED: Failed to send ACK for encrypted file's FILE_SIZE_MODE.")
            return False

        # Receive the actual encrypted file
        print(f"Receiving encrypted file ({CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME})...")
        if os.path.exists(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME): # Clean up before receiving
            os.remove(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME)
            
        if not get_file(client_socket, CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME, encrypted_file_size):
            print("TEST FAILED: get_file for encrypted file failed.")
            return False
        
        # Verification of the downloaded encrypted file
        if os.path.exists(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME) and os.path.getsize(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME) == encrypted_file_size:
            print(f"SUCCESS: Encrypted file received and saved as {CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME}, size {os.path.getsize(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME)} matches expected {encrypted_file_size}.")
            # Note: Further verification (decryption and content comparison) is outside the scope of this basic test.
            # With a fixed key/IV on the server, this encrypted file should be consistently the same for the same input.
            success = True
        else:
            print(f"TEST FAILED: Encrypted file verification failed. Exists: {os.path.exists(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME)}, Size: {os.path.getsize(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME) if os.path.exists(CLIENT_TEST_ENCRYPT_OUTPUT_FILENAME) else 'N/A'}")

    except socket.timeout:
        print("TEST FAILED: Socket timeout during encryption test.")
    except ConnectionRefusedError:
        print("TEST FAILED: Connection refused. Server might not be running.")
    except Exception as e:
        print(f"TEST FAILED: An error occurred during encryption test: {e}")
    finally:
        if client_socket:
            close_communication(client_socket)
    return success

if __name__ == "__main__":
    """
    Main execution block for the client-server interaction test script.
    
    This block orchestrates the test execution by:
    1. Printing a startup message and a reminder to run the C server.
    2. Calling `setup_test_environment()` to clean up artifacts from previous runs.
    3. Executing `test_screenshot_mode()` and printing its result.
    4. Executing `test_encrypt_mode()` and printing its result.
    5. Calling `cleanup_test_environment()` to remove files created during the tests.
    6. Printing an overall summary of the test outcomes.
    """
    print("Starting client-server interaction tests...")
    print(f"IMPORTANT: Ensure the C server is running and listening on {SERVER_ADDRESS}:{PORT}.")
    
    setup_test_environment() # Clean up before tests
    
    # Run Screenshot Test
    screenshot_passed = test_screenshot_mode()
    print(f"Screenshot Test Result: {'PASSED' if screenshot_passed else 'FAILED'}")
    
    print("-" * 40) # Separator for better readability
    
    # Run Encrypt Test
    encrypt_passed = test_encrypt_mode()
    print(f"Encrypt Test Result: {'PASSED' if encrypt_passed else 'FAILED'}")
    
    cleanup_test_environment() # Clean up after tests
    
    print("\nAll tests completed.")
    print("=" * 40) # Summary separator
    if screenshot_passed and encrypt_passed:
        print("Overall Test Status: ALL TESTS PASSED")
    else:
        print("Overall Test Status: SOME TESTS FAILED")
    print("=" * 40)
