from threading import Thread
from socket import socket

HEADER_SIZE = 32
ENCODE_TYPE = 'utf-8'


class Session(Thread):
    conn: socket

    def __init__(self, conn: socket, adr=None):
        Thread.__init__(self)
        self.running = True
        self.conn = conn
        self.callback = None
        self.clientName = "SERVER" if not adr else "%s:%d" % adr

    def setCallback(self, callback):
        self.callback = callback

    def send_command(self, command: str, message: str):
        """
        Mỗi khi gửi tin client sẽ gửi lên 1 header cho biết độ dài của các path
        độ dài command|command|độ dài message|message
        """

        command = command.encode('utf-8')
        command_len = self.make_len_message(command)

        self.conn.send(command_len)
        self.conn.send(command)

        message = message.encode('utf-8')
        message_len = self.make_len_message(message)

        self.conn.send(message_len)
        self.conn.send(message)

    def make_len_message(self, n: bytes):
        # Chèn space cho đủ header size
        len_message = str(len(n)).encode(ENCODE_TYPE).rjust(HEADER_SIZE, b' ')
        return len_message

    def debug(self, message: str):
        print(f"[{self.clientName}]: {message}")

    def receive_command(self):
        # Đọc 1 gói dữ liệu có độ dài HEADER_SIZE
        command_len = self.conn.recv(HEADER_SIZE).decode(ENCODE_TYPE)
        command = message = ''
        if command_len:
            # Vì lúc gửi chèn space ở trên hàm make_len_message
            # Nên lúc nhận phải bỏ khoảng trắng đi và đổi thành số
            command_len = int(command_len.strip())
            # Đọc 1 gói dữ liệu có độ dài command_len
            command = self.conn.recv(command_len).decode(ENCODE_TYPE)
            message_len = self.conn.recv(HEADER_SIZE).decode(ENCODE_TYPE)
            if message_len:
                message_len = int(message_len.strip())
                message = self.conn.recv(message_len).decode(ENCODE_TYPE)
        return command, message

    def run(self):
        while self.running:
            try:
                command, message = self.receive_command()
                if command:
                    self.debug(f"send command `{command}`")
                    if self.callback:
                        self.callback(self, command, message)
            except:
                self.running = False
        self.conn.close()
