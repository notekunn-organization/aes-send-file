import socket

IP = socket.gethostbyname(socket.gethostname())
PORT = 1923

ADDRESS = (IP, PORT)