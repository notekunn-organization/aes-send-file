import socket
from threading import Thread, active_count
from socket_config import PORT

ADDRESS = (socket.gethostbyname(socket.gethostname()), PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
clients = []
HEADER_SIZE = 32
FORMAT_TYPE = 'utf-8'

"""
Mỗi khi gửi tin client sẽ gửi lên 1 header cho biết độ dài của các path
độ dài command|command|độ dài message|message
"""


def handle_client(conn, adr):
    client_name = f"{adr[0]}:{adr[1]}"
    print("%s connected.\n" % client_name)

    connected = True
    while connected:
        try:
            command_len = conn.recv(HEADER_SIZE).decode(FORMAT_TYPE)
            if command_len:
                command_len = int(command_len.strip())
                command = conn.recv(command_len).decode(FORMAT_TYPE)
                message_len = conn.recv(HEADER_SIZE).decode(FORMAT_TYPE)
                message_len = int(message_len)
                message = conn.recv(message_len).decode(FORMAT_TYPE)
                print(f"[{client_name}] send command `{command}`")
                handler_command(client_name, command, message)
        except ConnectionResetError:
            conn.close()
            if conn in clients:
                clients.remove(conn)
        except :
            connected = False
    conn.close()


def handler_command(client_name, command: str, message: str):
    if command == 'login':
        return
    return


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
                client.send(message.encode(FORMAT_TYPE))
            except ConnectionResetError:
                if client in clients:
                    clients.remove(client)


# if __name__ == 'main':
print("Server staring in %s:%d" % ADDRESS)
start()
