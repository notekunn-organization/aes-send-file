import socket
from threading import Thread, active_count
from socket_config import ADDRESS

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)


def handle_client(conn, adr):
    print("%s:%d connected.\n" % adr)

    connected = True
    while connected:
        msg = conn.recv(2048).decode("utf-8")
        if len(msg) > 0:
            print(f"[{adr[0]}:{adr[1]}]: {msg}")
            if msg == 'quit':
                connected = False
            conn.send(msg.encode("utf-8"))
    conn.close()


def start():
    server.listen()
    while True:
        conn, adr = server.accept()
        thread = Thread(target=handle_client, args=(conn, adr))
        thread.start()
        print("[Active thread]: %d" % (active_count() -1))


# if __name__ == 'main':
print("Server staring in %s:%d" % ADDRESS)
start()
