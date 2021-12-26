import socket
from socket_config import ADDRESS
from session.Session import Session
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(*ADDRESS))
client.connect(ADDRESS)

session = Session(client)
session.start()
session.send_command("upload", "abcdef.txt")
session.send_command("upload", "abcdef.txt")
session.send_command("upload_content", "1111")
