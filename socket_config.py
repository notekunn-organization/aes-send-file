import socket
from decouple import config

IP = config("IP", socket.gethostbyname(socket.gethostname()))
PORT = int(config("PORT", "1975"))

ADDRESS = (IP, PORT)