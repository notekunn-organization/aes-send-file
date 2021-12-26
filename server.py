import socket
from typing import List
from threading import active_count
from socket_config import PORT
from session.Session import Session
import time
import json

ADDRESS = (socket.gethostbyname(socket.gethostname()), PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
clients = []
dictClient = {}
HEADER_SIZE = 32
ENCODE_TYPE = 'utf-8'
uploadProcess = {}

with open("./data.json", "r") as fpIn:
    fileUploaded = json.load(fpIn)


def store_json():
    with open('./data.json', 'w+') as fpOut:
        json.dump(fileUploaded, fpOut)


class Server:
    sessions: List[Session]

    def __init__(self):
        self.sessions = []

    def broadcast(self, clientName: str, command: str, message: str):
        for s in self.sessions:
            # Nếu khác client
            if s.clientName != clientName and s.running:
                s.send_command(command, str)

    def handle_command(self, session: Session, command: str, message: str):
        clientName = session.clientName
        if command == 'upload':
            if session.clientName in uploadProcess:
                session.send_command("error", "Bạn đang upload 1 file khác")
                return
            print(f"{session.clientName} upload file: {message}")
            uploadProcess[session.clientName] = message
            return
        if command == 'upload_content':
            if session.clientName not in uploadProcess:
                session.send_command("error", "Bạn chưa gửi yêu cầu upload file")
                return
            fileName = uploadProcess[session.clientName]
            hashedFile = time.strftime("%Y%m%d%H%M%S") + '-' + fileName
            print(f"{session.clientName} upload content for: {fileName}")
            with open(f"files/{fileName}", "w+") as fp:
                fp.write(message)
            fileUploaded.append({
                "id": len(fileUploaded) + 1,
                "author": session.clientName,
                "file_name": fileName,
                "location": hashedFile
            })
            store_json()
            del uploadProcess[session.clientName]
            self.broadcast(clientName, "new_file", "Alo")
            return
        if command == 'loadfile':
            return
        return

    def start(self):
        print("Server staring in %s:%d" % ADDRESS)
        server.listen()
        while True:
            conn, adr = server.accept()
            s = Session(conn, adr)
            self.sessions.append(s)
            s.setCallback(self.handle_command)
            s.start()
            print("[Active thread]: %d" % (active_count() - 1))


ser = Server()
ser.start()
