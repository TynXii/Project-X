#Client side implementation
#File should be run with .sh script


import struct
import socket
import os
import sys
from typing import Optional
from enum import Enum



class PacketModes(Enum):
    # Main Packet Modes
    SCREENSHOT_MODE = 1
    ENCRYPT_MODE = 2

    # Modes for handling main packet modes
    FILE_TRANSFER_MODE = 3
    ACK_MODE = 4
    FINAL_ACK_MODE = 5

class AckPacket(Enum):
    WAIT_FOR_ACK_PACKET = 'w'
    SEND_ACK_PACKET = 's'


PORT = 8080
MAGIC_NUMBER = 'HMS'.encode()
HEADER_FORMAT = '!3sBHH'
MAX_PAYLOAD_SIZE = 1016
HEADER_SIZE = 8
BUFFER_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE
DEFAULT_ENCRYPTED_FILE_NAME = "encrypted_file.txt"
DEFAULT_TO_ENCRYPT_FILE_NAME = "to_encrypt.txt"
DEFAULT_SCREENSHOT_FILE_NAME = "screenshot.jpg"
SERVER_ADDRESS = '0.0.0.0' # Replace with your server IP address. Leaving it as-is is also fine.

EXIT_OPTION = 3

class ProtocolPacket:
    def __init__(self, mode: int, payload: str, payload_length: int, checksum: int):
        self.magic_number = MAGIC_NUMBER
        self.mode = mode
        self.payload  = payload
        self.payload_length = payload_length
        self.checksum = checksum



def close_communication(socket: socket.socket) -> None:
    socket.close()
    print("Connection closed.")
    
    
def calculate_checksum(payload, payload_length) -> int:
        return ~sum(payload) & 0xFFFF

# Important to understand that if there should be no payload to the packet, the payload parameter should be set to None
def set_packet(mode: int, payload: Optional[str], payload_length: int, checksum: int) -> Optional[ProtocolPacket]:
    match mode:
        case PacketModes.FILE_TRANSFER_MODE | PacketModes.ENCRYPT_MODE:
            if checksum != calculate_checksum(payload, payload_length):
                print("Invalid checksum")
                return None
            return ProtocolPacket(mode, payload, payload_length, checksum)
        case PacketModes.ACK_MODE | PacketModes.FINAL_ACK_MODE | PacketModes.SCREENSHOT_MODE:
            return ProtocolPacket(mode, None, 0, 0)
        case _:
            print("Invalid packet mode")
            return None




# Serializes packet of ProtocolPacket, and returns the packet as a string.
def serialize_packet(packet: ProtocolPacket) -> str:
    header = struct.pack(HEADER_FORMAT, packet.magic_number, packet.mode, packet.payload_length, packet.checksum)
    buffer = header + packet.payload
    return buffer



# Connects to a server.
def initialize_communication(port : int, server_address: int) -> Optional[socket.socket]:
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_address, port))
    except socket.error as e:
        print(f"Socket error: {e}")
        return None


    return client_socket


# Sends a packet through a socket.
def send_packet(client_socket: socket.socket, given_packet: ProtocolPacket) -> Optional[int]:
    packet = serialize_packet(given_packet)
    retries = 0
    max_retries = 3
    while True:
        try:
            client_socket.sendall(packet)
        except BrokenPipeError:
            print("BrokenPipeError: The server has closed the connection.")
            close_communication(client_socket)
            return None
        except socket.timeout:
            print("socket.timeout: The operation timed out.")
            close_communication(client_socket)
            return None
        except ConnectionResetError:
            # If connection was reset, force to 
            print("ConnectionResetError: The connection was reset by the server.")
            if retries < max_retries:
                retries += 1
                continue
            close_communication(client_socket)
        except OSError as e:
            print(f"OSError: {e}")
            close_communication(client_socket)
            return None
        return 1



def handle_acknowledgment(client_socket: socket.socket, mode: int, action_mode: str) -> Optional[int]:
    temp_packet = set_packet(mode, None, 0, 0)
    match action_mode:
        case AckPacket.SEND_ACK_PACKET:
            if not send_packet(client_socket, temp_packet):
                print("Failed to send acknowledgment")
                return None
            return 1
        case AckPacket.WAIT_FOR_ACK_PACKET:
            data = client_socket.recv(HEADER_SIZE)
            if (not data) or (len(data) != HEADER_SIZE) or (data[len(MAGIC_NUMBER)] != mode):
                print("Data receiving failed.")
                return None
            return 1
            
        

            


def send_file_to_encrypt(client_socket: socket.socket, file_name: str) -> Optional[int]:
    with open(file_name, "rb") as file:
        data = file.read()

    remaining_data_size = len(data)

    # Used to track what bytes need to be sent next.
    start = 0
    stop = MAX_PAYLOAD_SIZE

    while (remaining_data_size):
        payload_size = BUFFER_SIZE if (remaining_data_size > BUFFER_SIZE) else remaining_data_size
        current_packet = set_packet(PacketModes.FILE_TRANSFER_MODE, data[start:stop], payload_size, calculate_checksum(data[stat:stop], payload_size))
        if not current_packet:
            print("Packet initialization failed.")
            return None
        
        if not send_packet(client_socket, current_packet):
            print("Packet sending failed.")
            return None

        if remaining_data_size < MAX_PAYLOAD_SIZE:
            if not handle_acknowledgment(client_socket, PacketModes.FINAL_ACK_MODE, AckPacket.WAIT_FOR_ACK_PACKET):
                return None
            else:
                return 1
        else:
            if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.WAIT_FOR_ACK_PACKET):
                return None

        start += payload_size
        stop += payload_size
        remaining_data_size -= payload_size


def get_file(client_socket: socket.socket, file_name: str, file_size: int) -> Optional[int]:
    file = open(file_name, "ab")
    extra_packet = 0 if (file_size % MAX_PAYLOAD_SIZE == 0) else 1
    remaining_data_size = file_size + HEADER_SIZE * (file_size // MAX_PAYLOAD_SIZE + extra_packet)

    while (remaining_data_size):
        packet_size = BUFFER_SIZE if (remaining_data_size < BUFFER_SIZE) else  remaining_data_size
        data = client_socket.recv(packet_size)
        if not data or (data[len(MAGIC_NUMBER)] != PacketModes.FILE_TRANSFER_MODE):
            print("Invalid packet.")
            return None
        file.write(data)

        if remaining_data_size < BUFFER_SIZE:
            if not handle_acknowledgment(client_socket, PacketModes.FINAL_ACK_MODEACK_MODE, AckPacket.SEND_ACK_PACKET):
                return None
            return 1
        else:
            if not handle_acknowledgment(client_socket, PacketModes.ACK_MODE, AckPacket.SEND_ACK_PACKET):
                return None
        remaining_data_size -= packet_size


def get_request() -> [Optional[int], Optional[str]]:
    print("\n=== Main Menu ===")
    print("1. Request a screenshot")
    print("2. Request encryption for a file")
    print("3. Exit")
    
    try:
        choice = int(input("Enter your choice (1/2/3): "))
    except ValueError:
        print("Invalid input! Please enter a number.")
        return [None, None]

    if choice == EXIT_OPTION:
        print("Exiting program, goodbye!")
        return [None, None]

    match choice:
        case PacketModes.SCREENSHOT_MODE:
            return [PacketModes.SCREENSHOT_MODE, None]
        case PacketModes.ENCRYPT_MODE:
            file_name = input("Enter file name to encrypt: ").strip()
            return [PacketModes.ENCRYPT_MODE, file_name]
        case _:
            print("Invalid option. Please try again.")
            return [None, None]



def make_request() -> Optional[int]:
    client_socket = initialize_communication(PORT, SERVER_ADDRESS)

    request = get_request()

    match request[0]:
        case None:
            pass
        case PacketModes.SCREENSHOT_MODE:
            file_size = client_socket.recv(BUFFER_SIZE)[HEADER_SIZE:]
            if not get_file(client_socket, DEFAULT_SCREENSHOT_FILE_NAME, file_size):
                print("File collecting failed.")
                close_communication(client_socket)
                return None
            print(f"Successfully downloaded screenshot and saved it as {DEFAULT_SCREENSHOT_FILE_NAME}")
            return 1
        case PacketModes.ENCRYPT_MODE:
            if not send_file_to_encrypt(client_socket, request[1]):
                print("File sending failed.")
                close_communication(client_socket)
                return None
            file_size = client_socket.recv(BUFFER_SIZE)[HEADER_SIZE:]
            if not get_file(client_socket, request[1], file_size):
                print("File collecting failed.")
                close_communication(client_socket)
                return None
            print(f"Successfully downloaded encrypted file and saved it as {DEFAULT_ENCRYPTED_FILE_NAME}")
            return 1
            