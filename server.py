import os
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
uploadProcess = {}
fileUploaded = []


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
                s.send_command(command, message)

    def handle_command(self, session: Session, command: str, message: str):
        clientName = session.clientName
        if command == 'upload':
            if clientName in uploadProcess:
                session.send_command("error", "Bạn đang upload 1 file khác")
                return
            print(f"{clientName} upload file: {message}")
            uploadProcess[clientName] = message
            return
        if command == 'upload_content':
            if clientName not in uploadProcess:
                session.send_command("error", "Bạn chưa gửi yêu cầu upload file")
                return
            fileName = uploadProcess[session.clientName]
            hashedFile = time.strftime("%Y%m%d%H%M%S") + '-' + fileName
            print(f"{clientName} upload content for: {fileName}")
            with open(f"files/{hashedFile}", "w+") as fp:
                fp.write(message)
            newFile = {
                "id": len(fileUploaded) + 1,
                "author": clientName,
                "file_name": fileName,
                "location": hashedFile
            }
            fileUploaded.append(newFile)
            store_json()
            del uploadProcess[clientName]
            self.broadcast(clientName, "new_file", session.encode_json(newFile))
            session.send_command("info", "Upload file thành công")
            return
        if command == 'load_file':
            session.send_command("load_file", session.encode_json(fileUploaded))
            return
        if command == 'download':
            id = int(message)
            fileToDownload = self.findFile(id)
            if not fileToDownload:
                session.send_command("error", "File không có trên hệ thống")
                return
            filePath = f"files/{fileToDownload['location']}"
            if not os.path.exists(filePath):
                session.send_command("error", "File thất lạc")
                return
            with open(filePath, "r") as fp:
                fileContent = fp.read()
                session.send_command("download", fileContent)
            return
        return

    def findFile(self, id: int):
        for i in range(len(fileUploaded)):
            if fileUploaded[i]["id"] == id:
                return fileUploaded[i]
        return id

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
