import os
import socket
import time
from threading import Thread
from AESManager import AESManager
from socket_config import ADDRESS

# aes = AESManager()
# PASSPHRASE = "secretkeyaes"
HEADER_SIZE = 32
ENCODE_TYPE = 'utf-8'
#
#
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(*ADDRESS))
client.connect(ADDRESS)


def send_command(command: str, message: str):
    message = message.encode('utf-8')
    # Gui do dai tin nhan phai chen cho du header size
    message_len = make_len_message(message)
    command = command.encode('utf-8')
    command_len = make_len_message(command)
    # command_len_message += b' ' * (HEADER_SIZE - len(command_len_message))
    client.send(command_len)
    client.send(command)
    client.send(message_len)
    client.send(message)


def make_len_message(n: str):
    len_message = str(len(n)).encode(ENCODE_TYPE).rjust(HEADER_SIZE, b' ')
    return len_message


send_command("upload", "abcd.txt")
send_command("upload_content", "cuong dep trai")
input()
send_command("upload", "abcde.txt")
send_command("upload_content", "noi dung file thu 2")
# send_command("upload_content", "day la noi dung file")
# input()
