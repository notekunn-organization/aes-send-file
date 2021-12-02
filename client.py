import os
import socket
import time
from threading import Thread
from AESManager import AESManager

aes = AESManager()
PASSPHRASE = "secretkeyaes"
HEADER = 1024
IP = socket.gethostbyname(socket.gethostname())
PORT = 1237

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(IP, PORT))
client.connect((IP, PORT))


def send_message(msg):
    client.send(msg.encode("utf-8"))


def handler_socket():
    msg = client.recv(2048).decode("utf-8")
    if msg:
        print("\nReceive a file, Decoding...")
        if len(msg) % 16 != 0:
            print("File is not encrypted by aes")

        file_name = time.strftime("%Y%m%d%H%M%S")
        file = open(f"files/{file_name}-receive.txt", "w+")
        file.write(msg)
        file.close()
        plain_text = aes.decrypt(PASSPHRASE, msg)
        file = open(f"files/{file_name}-result.txt", "w+")
        file.write(plain_text)
        file.close()
        print(f"File save in {file_name}-result.txt")


def input_mutiline():
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    text = '\n'.join(lines)
    return text


def main():
    while True:
        print("""
AES File Transfer
1) Create File
2) Send file
        """)
        choose = int(input("Choose one: "))
        if choose == 1:
            file_name = input("File name: ")
            print("Content of file:")
            file_content = input_mutiline()
            file = open(f"./files/{file_name}.txt", "w+")
            file.write(file_content)
            file.close()
            print(f"Saved file {file_name}.txt")
        if choose == 2:
            file_name = input("File to send: ")
            if not os.path.exists(f"./files/{file_name}.txt"):
                print("File is not exists")
                continue
            file = open(f"./files/{file_name}.txt", "r")
            file_content = (file.read())
            file.close()
            print("File content:\n%s" % file_content)
            cipher_text = aes.encrypt(PASSPHRASE, file_content)
            send_message(cipher_text)
            print("Send file success")


thread = Thread(target=handler_socket)
thread.start()

main()