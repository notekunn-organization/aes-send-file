import os
import socket
import time
from threading import Thread
from AESManager import AESManager
from socket_config import ADDRESS

# aes = AESManager()
# PASSPHRASE = "secretkeyaes"
HEADER_SIZE = 32
#
#
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(*ADDRESS))
client.connect(ADDRESS)


def send_command(command: str, message: str):
    message = message.encode('utf-8')
    # Gui do dai tin nhan phai chen cho du header size
    message_len = len(message)
    message_len_message = str(message_len).encode('utf-8').rjust(HEADER_SIZE, b' ')
    command = command.encode('utf-8')
    command_len = len(command)
    command_len_message = str(command_len).encode('utf-8').rjust(HEADER_SIZE, b' ')
    # command_len_message += b' ' * (HEADER_SIZE - len(command_len_message))
    client.send(command_len_message)
    client.send(command)
    client.send(message_len_message)
    client.send(message)


send_command("upload", "a" * 192)
# input()
