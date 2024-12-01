import struct
import socket
import os
import sys
from typing import Optional
from enum import Enum

class PacketModes(Enum):
    # Main Packet Modes
    SCREENSHOT_MODE = 0x01
    ENCRYPT_MODE = 0x02

    # Modes for handling main packet modes
    FILE_TRANSFER_MODE = 0x03
    ACK_MODE = 0x04
    FINAL_ACK_MODE = 0x05

class AckPacket(Enum):
    WAIT_FOR_ACK_PACKET = 'w'
    SEND_ACK_PACKET = 's'


PORT = 8080
MAGIC_NUMBER = 'HMS'.encode()
HEADER_FORMAT = '!3sBHH'
MAX_PAYLOAD_SIZE = 1016
HEADER_SIZE = 8
DEFAULT_ENCRYPTED_FILE_NAME = "encrypted_file.txt"
DEFAULT_SCREENSHOT_FILE_NAME = "screenshot.jpg"
SERVER_ADDRESS = '0.0.0.0' # Replace with your server IP address. Leaving it as-is is also fine.


class ProtocolPacket:
    def __init__(self, mode: str, payload: str, payload_length: int, checksum: int):
        self.magic_number = MAGIC_NUMBER
        self.mode = mode
        self.payload  = payload
        self.payload_length = payload_length
        self.checksum = checksum

    def calculate_checksum(self, payload, payload_length):
        return ~sum(payload) & 0xFFFF

def close_communication(socket: socket.socket) -> None:
    socket.close()
    print("Connection closed.")


def set_packet(mode: str, payload: Optional[str], payload_length: int, checksum: int) -> ProtocolPacket:
    match mode:
        case PacketModes.FILE_TRANSFER_MODE | PacketModes.ENCRYPT_MODE:
            return ProtocolPacket(mode, payload, payload_length, checksum)
        case PacketModes.ACK_MODE | PacketModes.FINAL_ACK_MODE | PacketModes.SCREENSHOT_MODE:
            return ProtocolPacket(mode, None, 0, 0)

def serialize_packet(packet: ProtocolPacket) -> str:
    header = struct.pack(HEADER_FORMAT, packet.magic_number, packet.mode, packet.payload_length, packet.checksum)
    buffer = header + packet.payload
    return buffer



def initialize_communication(port : int, server_address: int) -> socket.socket:
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_address, port))
    except socket.error as e:
        print(f"Socket error: {e}")

    return client_socket



def send_file_to_encrypt(client_socket: socket.socket, file_name: str) -> int:
    pass

def get_file():
    pass





    
    

    