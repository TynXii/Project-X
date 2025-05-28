"""
Client-side implementation for a custom protocol.

This module provides functionalities for a client to interact with a server
for operations like requesting screenshots and file encryption. It handles
packet creation, serialization, communication, and file transfer logic.
"""

import struct
import socket
import os
# import sys # sys module was imported but not used.
from typing import Optional, Tuple, List # Tuple and List were not explicitly used but good for type hints if needed later.
from enum import Enum
import binascii # For CRC32 calculation

# --- Protocol Definitions ---

class PacketModes(Enum):
    """
    Defines the various modes of operation for a protocol packet.
    These modes dictate the action to be performed or the type of data being sent.
    """
    # Main Packet Modes initiated by client
    SCREENSHOT_MODE = 1         # Client requests a screenshot.
    ENCRYPT_MODE = 2            # Client requests to encrypt a file.

    # Modes supporting main operations or data transfer
    FILE_TRANSFER_MODE = 3      # Packet contains a chunk of a file.
    ACK_MODE = 4                # Acknowledgment packet.
    FINAL_ACK_MODE = 5          # Final acknowledgment packet in a sequence.
    FILE_SIZE_MODE = 6          # Packet (typically from server) contains file size information.

class AckPacket(Enum):
    """
    Defines actions for the handle_acknowledgment function,
    specifying whether to wait for or send an ACK.
    """
    WAIT_FOR_ACK_PACKET = 'w'   # Instructs to wait for an ACK.
    SEND_ACK_PACKET = 's'       # Instructs to send an ACK.

# --- Protocol Constants ---
PORT = 8080                             #: Server port number.
MAGIC_NUMBER = b'HMS'                   #: Magic number to identify protocol packets.
HEADER_FORMAT = '!3sBH I'               #: Struct format string for packet header (Network Byte Order).
                                        # (Magic (3s), Mode (B), PayloadLength (H), Checksum (I))
MAX_PAYLOAD_SIZE = 1016                 #: Maximum size of the payload data in a packet.
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) #: Calculated size of the packet header.
BUFFER_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE #: Default buffer size for receiving packets.

# Default filenames used by the client for saving received files.
DEFAULT_ENCRYPTED_FILE_NAME = "encrypted_file.txt"
# DEFAULT_TO_ENCRYPT_FILE_NAME = "to_encrypt.txt" # This constant seems unused.
DEFAULT_SCREENSHOT_FILE_NAME = "screenshot.jpg"

# Server IP address - for local testing. Change to actual server IP in a real deployment.
SERVER_ADDRESS = '127.0.0.1'
EXIT_OPTION = 3                         #: User input option to exit the client application.


# --- Data Structures ---

class ProtocolPacket:
    """
    Represents a packet in the custom protocol.

    Attributes:
        magic_number (bytes): The magic number ('HMS') identifying the protocol.
        mode (int): The operational mode of the packet (see PacketModes).
        payload (bytes): The data payload of the packet.
        payload_length (int): The length of the payload in bytes.
        checksum (int): The CRC32 checksum of the payload.
    """
    def __init__(self, mode: int, payload: bytes, payload_length: int, checksum: int):
        """
        Initializes a ProtocolPacket instance.

        Args:
            mode: The packet mode (integer value from PacketModes).
            payload: The byte string for the packet's payload.
            payload_length: The length of the payload.
            checksum: The CRC32 checksum of the payload.
        """
        self.magic_number: bytes = MAGIC_NUMBER
        self.mode: int = mode
        self.payload: bytes = payload # Ensure payload is bytes
        self.payload_length: int = payload_length
        self.checksum: int = checksum


# --- Core Protocol Functions ---

def close_communication(client_socket: socket.socket) -> None:
    """
    Closes the given client socket.

    Args:
        client_socket: The socket object to close.
    """
    if client_socket:
        client_socket.close()
    print("Connection closed.")


def calculate_crc32(data: bytes) -> int:
    """
    Calculates the CRC32 checksum for the given data.

    Args:
        data: The byte string for which to calculate the checksum.

    Returns:
        The CRC32 checksum as an unsigned 32-bit integer.
    """
    return binascii.crc32(data) & 0xFFFFFFFF


def set_packet(mode: int, payload: Optional[bytes] = None) -> Optional[ProtocolPacket]:
    """
    Creates and initializes a ProtocolPacket instance.

    This function calculates the payload length and checksum internally.
    For modes that inherently have no payload (e.g., ACK, initial SCREENSHOT request),
    the payload should be None, and the checksum will be 0.

    Args:
        mode: The packet mode (e.g., PacketModes.SCREENSHOT_MODE).
        payload: The payload data as a byte string. Defaults to None for payload-less packets.

    Returns:
        A ProtocolPacket instance if successful, None otherwise (e.g., if payload exceeds max size).
    """
    mode_value = mode.value if isinstance(mode, PacketModes) else mode
    
    actual_payload = payload if payload is not None else b''
    payload_length = len(actual_payload)
    actual_checksum = 0 # Default checksum for payload-less packets

    if payload_length > 0:
        # This check is technically redundant if actual_payload is derived correctly,
        # but kept for logical clarity if payload handling becomes more complex.
        if payload is None: 
             print(f"Error: Payload is None but payload_length {payload_length} > 0 for mode {mode_value}.")
             return None
        actual_checksum = calculate_crc32(actual_payload)
    # For specific modes that are defined as payload-less, ensure checksum is 0.
    # This is implicitly handled if payload_length is 0, but can be made explicit if needed.
    elif mode_value in (
        PacketModes.ACK_MODE.value,
        PacketModes.FINAL_ACK_MODE.value,
        PacketModes.SCREENSHOT_MODE.value # Client's initial SCREENSHOT_MODE request has no payload
    ):
        actual_checksum = 0 # Explicitly ensure checksum is 0 for these modes
    
    # Check if payload exceeds maximum allowed size
    if payload_length > MAX_PAYLOAD_SIZE:
        print(f"Error: Payload length {payload_length} for mode {mode_value} "
              f"exceeds MAX_PAYLOAD_SIZE {MAX_PAYLOAD_SIZE}.")
        return None

    return ProtocolPacket(mode_value, actual_payload, payload_length, actual_checksum)


def serialize_packet(packet: ProtocolPacket) -> bytes:
    """
    Serializes a ProtocolPacket object into a byte string for network transmission.

    Uses the HEADER_FORMAT to pack header fields in network byte order.

    Args:
        packet: The ProtocolPacket object to serialize.

    Returns:
        A byte string representing the serialized packet.
    """
    # Ensure mode is its integer value for packing
    mode_value = packet.mode.value if isinstance(packet.mode, PacketModes) else packet.mode
    
    header = struct.pack(HEADER_FORMAT, 
                         packet.magic_number, 
                         mode_value, 
                         packet.payload_length, 
                         packet.checksum)
    # Concatenate header with payload (payload might be empty bytes b'')
    return header + packet.payload


def initialize_communication(port: int, server_address: str) -> Optional[socket.socket]:
    """
    Initializes a TCP socket and connects to the server.

    Args:
        port: The port number of the server.
        server_address: The IP address or hostname of the server.

    Returns:
        A connected socket object if successful, None otherwise.
    """
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for socket operations (e.g., 10 seconds)
        # client_socket.settimeout(10.0) # Optional: add if timeouts are desired globally
        client_socket.connect((server_address, port))
        print(f"Connected to server at {server_address}:{port}")
        return client_socket
    except socket.timeout:
        print(f"Socket error: Connection attempt to {server_address}:{port} timed out.")
        return None
    except socket.error as e:
        print(f"Socket error: {e} when trying to connect to {server_address}:{port}.")
        return None
    except Exception as e: # Catch any other unexpected errors during connection
        print(f"An unexpected error occurred during connection: {e}")
        return None


def send_packet(client_socket: socket.socket, packet_to_send: ProtocolPacket) -> bool:
    """
    Sends a prepared ProtocolPacket over the given socket.

    Serializes the packet before sending. Includes basic retry logic for send failures.

    Args:
        client_socket: The connected client socket.
        packet_to_send: The ProtocolPacket object to send.

    Returns:
        True if the packet was sent successfully, False otherwise.
    """
    serialized_data = serialize_packet(packet_to_send)
    # Basic retry mechanism (can be expanded if needed)
    max_retries = 3
    for attempt in range(max_retries):
        try:
            client_socket.sendall(serialized_data)
            return True # Success
        except socket.timeout:
            print(f"Send attempt {attempt + 1} timed out.")
            if attempt == max_retries - 1:
                close_communication(client_socket)
                return False
            # time.sleep(0.5) # Optional: wait before retry
        except BrokenPipeError:
            print("BrokenPipeError: Server closed the connection during send.")
            close_communication(client_socket)
            return False
        except ConnectionResetError:
            print("ConnectionResetError: Connection reset by server during send.")
            close_communication(client_socket)
            return False
        except OSError as e:
            print(f"OSError during send: {e}")
            close_communication(client_socket)
            return False
    return False # Should be unreachable if loop logic is correct


def handle_acknowledgment(client_socket: socket.socket, 
                          expected_ack_mode: PacketModes, # Renamed for clarity if waiting
                          action_mode: AckPacket) -> bool:
    """
    Manages sending or waiting for acknowledgment (ACK) packets.

    Args:
        client_socket: The client socket.
        expected_ack_mode:
            - If action_mode is SEND_ACK_PACKET: This is the type of ACK to send (ACK_MODE or FINAL_ACK_MODE).
            - If action_mode is WAIT_FOR_ACK_PACKET: This is the expected mode of the ACK packet to receive.
        action_mode: Specifies the action: AckPacket.WAIT_FOR_ACK_PACKET or AckPacket.SEND_ACK_PACKET.

    Returns:
        True if the action was successful (ACK sent or valid ACK received), False otherwise.
    """
    if action_mode == AckPacket.SEND_ACK_PACKET:
        # 'expected_ack_mode' here is the type of ACK to send (ACK_MODE or FINAL_ACK_MODE)
        ack_to_send = set_packet(expected_ack_mode) 
        if not ack_to_send:
            print(f"Failed to create ACK packet for mode {expected_ack_mode.name}")
            return False
        if not send_packet(client_socket, ack_to_send):
            print(f"Failed to send ACK packet for mode {expected_ack_mode.name}")
            return False
        return True
    elif action_mode == AckPacket.WAIT_FOR_ACK_PACKET:
        try:
            header_data = client_socket.recv(HEADER_SIZE)
            if not header_data or len(header_data) != HEADER_SIZE:
                print(f"ACK Error: Did not receive complete header. Expected {HEADER_SIZE}, Got {len(header_data) if header_data else 0}.")
                return False

            magic_recv, mode_recv, p_len_recv, checksum_recv = struct.unpack(HEADER_FORMAT, header_data)
            
            expected_mode_value = expected_ack_mode.value

            if magic_recv != MAGIC_NUMBER:
                print(f"ACK Error: Invalid magic number. Got: {magic_recv.decode(errors='ignore')}")
                return False
            if mode_recv != expected_mode_value:
                print(f"ACK Error: Unexpected mode. Expected {expected_ack_mode.name} ({expected_mode_value}), Got: {mode_recv}")
                return False
            if p_len_recv != 0:
                print(f"ACK Error: Payload length should be 0. Got: {p_len_recv}")
                return False
            if checksum_recv != 0:
                print(f"ACK Error: Checksum should be 0. Got: {checksum_recv}")
                return False
            
            print(f"Received valid {expected_ack_mode.name}.")
            return True # Successfully received and validated ACK
        except socket.timeout:
            print("Timeout while waiting for ACK.")
            return False
        except struct.error as e:
            print(f"Error unpacking ACK header: {e}")
            return False
        except Exception as e:
            print(f"An unexpected error occurred while waiting for ACK: {e}")
            return False
    else:
        print(f"Invalid action_mode '{action_mode}' in handle_acknowledgment.")
        return False

            
def send_file_to_encrypt(client_socket: socket.socket, file_name: str) -> bool:
    """
    Sends the content of a specified file to the server for encryption.

    The file is read and sent in chunks. Each chunk is a FILE_TRANSFER_MODE packet.
    The function handles the ACK protocol with the server for each chunk.

    Args:
        client_socket: The connected client socket.
        file_name: The path to the file to be sent.

    Returns:
        True if the file was sent successfully and all ACKs received, False otherwise.
    """
    try:
        with open(file_name, "rb") as file:
            data = file.read()
    except IOError as e:
        print(f"Error opening or reading file '{file_name}': {e}")
        return False

    remaining_data_size = len(data)
    start_index = 0

    while remaining_data_size > 0:
        payload_size = min(MAX_PAYLOAD_SIZE, remaining_data_size)
        payload_chunk = data[start_index : start_index + payload_size]
        
        current_packet = set_packet(PacketModes.FILE_TRANSFER_MODE, payload_chunk)
        if not current_packet:
            print(f"Failed to create FILE_TRANSFER_MODE packet for '{file_name}'.")
            return False
        
        if not send_packet(client_socket, current_packet):
            print(f"Failed to send data chunk for '{file_name}'.")
            return False

        remaining_data_size -= payload_size
        start_index += payload_size
        
        # Determine expected ACK type
        expected_ack = PacketModes.FINAL_ACK_MODE if remaining_data_size == 0 else PacketModes.ACK_MODE
        print(f"Data chunk sent. Waiting for {expected_ack.name}...")
        if not handle_acknowledgment(client_socket, expected_ack, AckPacket.WAIT_FOR_ACK_PACKET):
            print(f"Failed to receive {expected_ack.name} after sending chunk of '{file_name}'.")
            return False
            
    print(f"File '{file_name}' sent successfully.")
    return True


def get_file(client_socket: socket.socket, output_file_name: str, total_file_size: int) -> bool:
    """
    Receives a file from the server and saves it locally.

    Handles receiving file data in chunks (FILE_TRANSFER_MODE packets) and sending
    appropriate ACKs (ACK_MODE, FINAL_ACK_MODE) back to the server.

    Args:
        client_socket: The connected client socket.
        output_file_name: The name to save the received file as.
        total_file_size: The total expected size of the file to be received.

    Returns:
        True if the file was received successfully, False otherwise.
    """
    bytes_received_total = 0
    # Ensure file is opened in binary write mode, truncating if it exists
    try:
        with open(output_file_name, "wb") as file:
            while bytes_received_total < total_file_size:
                # Calculate expected size of the next packet (header + payload chunk)
                # This assumes server sends payload chunks up to MAX_PAYLOAD_SIZE
                expected_payload_this_packet = min(MAX_PAYLOAD_SIZE, total_file_size - bytes_received_total)
                expected_full_packet_size = HEADER_SIZE + expected_payload_this_packet
                
                print(f"Expecting packet of approx {expected_full_packet_size} bytes for file '{output_file_name}'...")
                # Receive the full packet (header + payload)
                packet_data = client_socket.recv(expected_full_packet_size)
                if not packet_data:
                    print("Connection closed by server while receiving file.")
                    return False
                
                if len(packet_data) < HEADER_SIZE:
                    print(f"Received data too short for a header: {len(packet_data)} bytes.")
                    return False

                # Unpack header
                header = packet_data[:HEADER_SIZE]
                magic, mode, payload_len_from_header, checksum_from_header = struct.unpack(HEADER_FORMAT, header)
                
                # Validate header
                if magic != MAGIC_NUMBER:
                    print(f"Invalid magic number in received file packet: {magic.decode(errors='ignore')}")
                    return False
                if mode != PacketModes.FILE_TRANSFER_MODE.value:
                    print(f"Unexpected mode in file transfer. Expected {PacketModes.FILE_TRANSFER_MODE.value}, Got: {mode}")
                    return False
                
                # Extract payload
                payload_data = packet_data[HEADER_SIZE:]
                if len(payload_data) != payload_len_from_header:
                    print(f"Payload length mismatch. Header: {payload_len_from_header}, Actual: {len(payload_data)}")
                    return False

                # Validate payload checksum
                if calculate_crc32(payload_data) != checksum_from_header:
                    print("Checksum mismatch for received file data packet.")
                    return False

                file.write(payload_data)
                bytes_received_total += len(payload_data)
                print(f"Received {bytes_received_total}/{total_file_size} bytes for '{output_file_name}'.")

                # Send ACK for this data packet
                ack_type_to_send = PacketModes.FINAL_ACK_MODE if bytes_received_total == total_file_size else PacketModes.ACK_MODE
                print(f"Sending {ack_type_to_send.name} for received chunk...")
                if not handle_acknowledgment(client_socket, ack_type_to_send, AckPacket.SEND_ACK_PACKET):
                    print(f"Failed to send {ack_type_to_send.name} during get_file.")
                    return False
            
            if bytes_received_total == total_file_size:
                print(f"File '{output_file_name}' received successfully.")
                return True
            else:
                print(f"File transfer incomplete. Expected {total_file_size}, Got {bytes_received_total}.")
                return False

    except IOError as e:
        print(f"Error opening or writing file '{output_file_name}': {e}")
        return False
    except socket.timeout:
        print("Socket timeout during get_file.")
        return False
    except struct.error as e:
        print(f"Struct unpacking error during get_file: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during get_file: {e}")
        return False


def get_request() -> Tuple[Optional[PacketModes], Optional[str]]:
    """
    Prompts the user to select an operation (screenshot, encrypt, exit)
    and gets necessary input (e.g., filename for encryption).

    Returns:
        A tuple: (PacketModes enum member or None, filename string or None).
        Returns (None, None) if the user chooses to exit or provides invalid input
        that prevents further processing.
    """
    print("\n=== Main Menu ===")
    print(f"1. Request a screenshot (saved as {DEFAULT_SCREENSHOT_FILE_NAME})")
    print("2. Request encryption for a file")
    print(f"{EXIT_OPTION}. Exit")
    
    try:
        choice = int(input(f"Enter your choice (1/2/{EXIT_OPTION}): "))
    except ValueError:
        print("Invalid input! Please enter a number.")
        return None, None

    if choice == EXIT_OPTION:
        print("Exiting program, goodbye!")
        return None, None
    
    # Convert choice to PacketModes enum if possible
    # Note: direct int to enum mapping is not standard for Enum unless using IntEnum or similar.
    # Here, we map manually based on menu options.
    if choice == 1: # Assuming 1 maps to SCREENSHOT_MODE
        return PacketModes.SCREENSHOT_MODE, None
    elif choice == 2: # Assuming 2 maps to ENCRYPT_MODE
        file_name = input("Enter file name to encrypt: ").strip()
        if not file_name:
            print("Error: No filename provided.")
            return None, None
        if not os.path.isfile(file_name):
            print(f"Error: File '{file_name}' not found or is not a regular file.")
            return None, None
        return PacketModes.ENCRYPT_MODE, file_name
    else:
        print("Invalid option. Please try again.")
        return None, None


def make_request() -> bool:
    """
    Main client function to handle user requests.

    Connects to the server, gets user input for the desired operation,
    and orchestrates the communication with the server to fulfill the request.

    Returns:
        True if the operation was nominally completed (even if specific sub-steps failed but were handled),
        False if a critical setup error occurred (e.g., connection failure).
    """
    client_socket = initialize_communication(PORT, SERVER_ADDRESS)
    if not client_socket:
        print("Failed to initialize communication with the server. Aborting.")
        return False # Critical failure

    mode_requested_enum, file_name_param = get_request()

    if mode_requested_enum is None: # User chose exit or provided invalid input in get_request
        if client_socket: 
            close_communication(client_socket)
        return True # Nominal completion (user exited or bad input handled by get_request)

    mode_requested_value = mode_requested_enum.value
    initial_packet_payload = b''
    # initial_payload_length = 0 # Not needed as set_packet derives length

    # Prepare payload for initial ENCRYPT_MODE request (file size)
    if mode_requested_enum == PacketModes.ENCRYPT_MODE:
        # File existence is already checked in get_request
        try:
            original_file_size = os.path.getsize(file_name_param)
            initial_packet_payload = struct.pack("!Q", original_file_size) # 8-byte unsigned long long
            # initial_payload_length = len(initial_packet_payload) # set_packet derives this
        except OSError as e:
            print(f"Error getting file size for '{file_name_param}': {e}")
            close_communication(client_socket)
            return True # Handled error, nominal completion
        except struct.error as e:
            print(f"Error packing file size: {e}")
            close_communication(client_socket)
            return True # Handled error

    # Create the initial command packet (SCREENSHOT_MODE or ENCRYPT_MODE)
    # set_packet calculates checksum internally.
    command_packet = set_packet(mode_requested_value, initial_packet_payload)

    if not command_packet:
        print(f"Failed to create initial command packet for {mode_requested_enum.name}.")
        close_communication(client_socket)
        return True # Handled error

    print(f"Sending {mode_requested_enum.name} request to server...")
    if not send_packet(client_socket, command_packet):
        print(f"Failed to send initial command packet for {mode_requested_enum.name}.")
        # send_packet calls close_communication on critical send errors
        return True # Handled error

    # --- Handle server's response specific to the mode ---
    operation_successful = False
    if mode_requested_enum == PacketModes.SCREENSHOT_MODE:
        print("Waiting for screenshot file size from server...")
        try:
            # 1. Receive FILE_SIZE_MODE packet header
            fsm_header_data = client_socket.recv(HEADER_SIZE)
            if not fsm_header_data or len(fsm_header_data) != HEADER_SIZE:
                print("Failed to receive complete FILE_SIZE_MODE header for screenshot.")
            else:
                fsm_magic, fsm_mode, fsm_payload_len, fsm_checksum = struct.unpack(HEADER_FORMAT, fsm_header_data)
                # 2. Validate header
                if fsm_magic != MAGIC_NUMBER or fsm_mode != PacketModes.FILE_SIZE_MODE.value or fsm_payload_len != 8:
                    print("Invalid FILE_SIZE_MODE packet received for screenshot (header).")
                else:
                    # 3. Receive payload (file size)
                    fsm_payload_data = client_socket.recv(fsm_payload_len)
                    if not fsm_payload_data or len(fsm_payload_data) != fsm_payload_len:
                        print("Failed to receive complete FILE_SIZE_MODE payload for screenshot.")
                    # 4. Validate payload checksum
                    elif calculate_crc32(fsm_payload_data) != fsm_checksum:
                        print("FILE_SIZE_MODE checksum mismatch for screenshot.")
                    else:
                        screenshot_file_size = struct.unpack("!Q", fsm_payload_data)[0]
                        print(f"Received screenshot file size: {screenshot_file_size} bytes.")
                        # 5. Send ACK for FILE_SIZE_MODE
                        if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.SEND_ACK_PACKET):
                            print("Failed to send ACK for screenshot FILE_SIZE_MODE.")
                        # 6. Receive the screenshot file
                        elif get_file(client_socket, DEFAULT_SCREENSHOT_FILE_NAME, screenshot_file_size):
                            print(f"Screenshot successfully downloaded as {DEFAULT_SCREENSHOT_FILE_NAME}")
                            operation_successful = True
                        else:
                            print("Screenshot file download failed.")
        except socket.timeout:
            print("Socket timeout during screenshot operation.")
        except Exception as e:
            print(f"An error occurred during screenshot operation: {e}")

    elif mode_requested_enum == PacketModes.ENCRYPT_MODE:
        print(f"ENCRYPT_MODE: Sending file content of '{file_name_param}'...")
        # 1. Send the file to be encrypted
        if not send_file_to_encrypt(client_socket, file_name_param):
            print(f"Sending file content for '{file_name_param}' failed.")
        else:
            print("File content sent. Waiting for encrypted file size from server...")
            try:
                # 2. Receive FILE_SIZE_MODE packet header for encrypted file
                efs_header_data = client_socket.recv(HEADER_SIZE)
                if not efs_header_data or len(efs_header_data) != HEADER_SIZE:
                    print("Failed to receive complete FILE_SIZE_MODE header for encrypted file.")
                else:
                    efs_magic, efs_mode, efs_payload_len, efs_checksum = struct.unpack(HEADER_FORMAT, efs_header_data)
                    # 3. Validate header
                    if efs_magic != MAGIC_NUMBER or efs_mode != PacketModes.FILE_SIZE_MODE.value or efs_payload_len != 8:
                        print("Invalid FILE_SIZE_MODE packet received for encrypted file (header).")
                    else:
                        # 4. Receive payload (encrypted file size)
                        efs_payload_data = client_socket.recv(efs_payload_len)
                        if not efs_payload_data or len(efs_payload_data) != efs_payload_len:
                            print("Failed to receive complete FILE_SIZE_MODE payload for encrypted file.")
                        # 5. Validate payload checksum
                        elif calculate_crc32(efs_payload_data) != efs_checksum:
                            print("Encrypted FILE_SIZE_MODE checksum mismatch.")
                        else:
                            encrypted_file_size = struct.unpack("!Q", efs_payload_data)[0]
                            print(f"Received encrypted file size: {encrypted_file_size} bytes.")
                            # 6. Send ACK for FILE_SIZE_MODE
                            if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.SEND_ACK_PACKET):
                                print("Failed to send ACK for encrypted file's FILE_SIZE_MODE.")
                            # 7. Receive the encrypted file
                            elif get_file(client_socket, DEFAULT_ENCRYPTED_FILE_NAME, encrypted_file_size):
                                print(f"Encrypted file successfully downloaded as {DEFAULT_ENCRYPTED_FILE_NAME}")
                                operation_successful = True
                            else:
                                print("Encrypted file download failed.")
            except socket.timeout:
                print("Socket timeout during encryption operation post-file send.")
            except Exception as e:
                print(f"An error occurred during encryption operation post-file send: {e}")
    else:
        print(f"Error: Unsupported mode {mode_requested_enum.name} in make_request final handling.")

    close_communication(client_socket)
    return operation_successful # Returns True if the core file transfer (get_file) succeeded
