import socket
from threading import Thread, active_count
from socket_config import PORT

ADDRESS = (socket.gethostbyname(socket.gethostname()), PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
clients = []
dictClient = {}
HEADER_SIZE = 32
ENCODE_TYPE = 'utf-8'

"""
Mỗi khi gửi tin client sẽ gửi lên 1 header cho biết độ dài của các path
độ dài command|command|độ dài message|message
"""

uploadProcess = {}


def handle_client(conn, adr):
    client_name = f"{adr[0]}:{adr[1]}"
    print("%s connected.\n" % client_name)
    dictClient[client_name] = conn

    connected = True
    while connected:
        try:
            command_len = conn.recv(HEADER_SIZE).decode(ENCODE_TYPE)
            if command_len:
                command_len = int(command_len.strip())
                command = conn.recv(command_len).decode(ENCODE_TYPE)
                message_len = conn.recv(HEADER_SIZE).decode(ENCODE_TYPE)
                message_len = int(message_len)
                message = conn.recv(message_len).decode(ENCODE_TYPE)
                print(f"[{client_name}] send command `{command}`")
                handler_command(client_name, command, message)
        except:
            print("OUT")
            connected = False

    if client_name in dictClient:
        del dictClient[client_name]
    conn.close()


def handler_command(client_name, command: str, message: str):
    if command == 'upload':
        if client_name in uploadProcess:
            print("Ban dang up load 1 file khac")
            return
        print(f"{client_name} upload file: {message}")
        uploadProcess[client_name] = message
        return
    if command == 'upload_content':
        if client_name not in uploadProcess:
            print("Ban chua gui yeu cau upload file")
            return
        print(f"{client_name} upload content for: {uploadProcess[client_name]}")
        del uploadProcess[client_name]
        return
    return


def send_command(client, command: str, message: str):
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


def start():
    server.listen()
    while True:
        conn, adr = server.accept()
        clients.append(conn)
        thread = Thread(target=handle_client, args=(conn, adr))
        thread.start()
        print("[Active thread]: %d" % (active_count() - 1))


def broadcast(message, conn):
    for client in clients:
        if client != conn:
            try:
                client.send(message.encode(ENCODE_TYPE))
            except ConnectionResetError:
                if client in clients:
                    clients.remove(client)


# if __name__ == 'main':
print("Server staring in %s:%d" % ADDRESS)
start()
