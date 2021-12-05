import os
from threading import Thread
from tkinter import *
from tkinter import ttk, filedialog as fd, messagebox as mb
from AESManager import AESManager
import socket
from socket_config import ADDRESS

file_ext = [
    ('Text File', '*.txt')
]
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(*ADDRESS))
client.connect(ADDRESS)


class GUI(Tk):
    def __init__(self):
        super().__init__()
        self.geometry('500x400')
        self.title('AES File Transfer')
        self.iconbitmap('icon.ico')
        self.cipher_key: ttk.Entry = None
        self.aes_type: ttk.Combobox = None
        self.cipher_text: Text = None
        self.plain_text: Text = None
        self.setup_gui()
        self.start_socket()

    def setup_gui(self):
        row = ttk.Frame(self)
        lbl = ttk.Label(row, text="AES SEND FILE", anchor='w', font=("JetBrains Mono", 10))
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.config(anchor=N)
        lbl.pack()

        row = ttk.Frame(self)
        lbl = ttk.Label(row, width=16, text="Cipher Key: ", anchor='w')
        self.cipher_key = entry = ttk.Entry(row)
        entry.configure(font=("JetBrains Mono", 10))
        # current_type = StringVar()
        self.aes_type = aes_type_cbb = ttk.Combobox(row, width=10, state='readonly',
                                                    values=['AES-128', 'AES-192', 'AES-256'])
        aes_type_cbb.current(0)
        aes_type_cbb.configure(font=("JetBrains Mono", 10))
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.pack(side=LEFT)
        aes_type_cbb.pack(side=RIGHT, padx=5)
        entry.pack(side=LEFT, expand=True, fill=X)

        row = ttk.Frame(self)
        lbl = ttk.Label(row, width=16, text="Plain Text: ", anchor='w')
        self.plain_text = txt = Text(row, height=5)
        txt.configure(font=("JetBrains Mono", 12))

        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.pack(side=LEFT)
        txt.pack(fill=BOTH)

        spr = ttk.Separator(self, orient='horizontal')
        spr.pack(fill=X, pady=5, padx=10)

        row = ttk.Frame(self)
        lbl = ttk.Label(row, width=16, text="Cipher Text: ")
        self.cipher_text = txt = Text(row, height=5)
        txt.configure(font=("JetBrains Mono", 12))

        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.pack(side=LEFT)
        txt.pack(fill=BOTH)

        row = Frame(self)
        row.pack(side=BOTTOM, fill=X, padx=15, pady=15)
        for i in range(5):
            row.columnconfigure(i, weight=1)
        ttk.Button(row, text="Đọc file", command=self.load_plain_text) \
            .grid(row=0, column=0)
        ttk.Button(row, text="Lưu file", command=self.save_plain_text) \
            .grid(row=0, column=1)
        ttk.Button(row, text="Gửi file", command=self.send_file) \
            .grid(row=0, column=2)
        ttk.Button(row, text="Mã hóa", command=self.do_encrypt) \
            .grid(row=0, column=3)
        ttk.Button(row, text="Giải mã", command=self.do_decrypt) \
            .grid(row=0, column=4)

    def load_plain_text(self, *args):
        file_path = fd.askopenfilename(title="Chọn file Plain Text", defaultextension=file_ext, filetypes=file_ext)
        if not file_path:
            return
        if not os.path.exists(file_path):
            mb.showerror("Lỗi đọc file", "Đường dẫn không tồn tại")
            return
        file = open(file_path, "r")
        file_content = file.read()
        file.close()
        self.plain_text.delete(1.0, END)
        self.plain_text.insert(1.0, file_content)

    def save_plain_text(self, *args):
        file_path = fd.asksaveasfilename(title="Lưu plain text", defaultextension=file_ext, filetypes=file_ext)
        if not file_path:
            return
        file = open(file_path, "w+")
        file_content = self.plain_text.get(1.0, END)
        file.write(file_content)
        file.close()

        mb.showinfo("Lưu plain text", "Lưu file thành công")

    def do_encrypt(self, *args):
        try:
            plain_text = self.plain_text.get(0.0, END)[:-1]  # bo 1 ky tu \n cuoi cung
            cipher_key = self.cipher_key.get()
            if len(cipher_key) == 0:
                mb.showerror("Lỗi", "Vui lòng nhập cipher key")
                return
            if len(plain_text) == 0:
                mb.showerror("Lỗi", "Vui lòng nhập plain text")
                return
            aes_type = self.aes_type.get()
            aes = AESManager(int(aes_type[4:]))
            cipher_text = aes.encrypt(cipher_key, plain_text)
            self.cipher_text.delete(0.0, END)
            self.cipher_text.insert(0.0, cipher_text)
            mb.showinfo("Mã hóa", "Mã hóa thành công")
        except:
            mb.showerror("Lỗi", "Có lỗi xảy ra")

    def do_decrypt(self, *args):
        try:
            cipher_text = self.cipher_text.get(0.0, END)[:-1]  # bo 1 ky tu \n cuoi cung
            cipher_key = self.cipher_key.get()
            if len(cipher_key) == 0:
                mb.showerror("Lỗi", "Vui lòng nhập cipher key")
                return
            if len(cipher_text) == 0 or len(cipher_text) % 32 != 0:
                mb.showerror("Lỗi", "Cipher text không hợp lệ")
                return

            aes_type = self.aes_type.get()
            aes = AESManager(int(aes_type[4:]))
            plain_text = aes.decrypt(cipher_key, cipher_text)
            self.plain_text.delete(0.0, END)
            self.plain_text.insert(0.0, plain_text)
            mb.showinfo("Giải mã", "Giải mã thành công")
        except:
            mb.showerror("Lỗi", "Có lỗi xảy ra")

    def start_socket(self):
        thread = Thread(target=self.receive_file)
        thread.start()

    def receive_file(self):
        while True:
            msg = client.recv(2048).decode("utf-8")
            if not msg:
                continue
            confirm = mb.askyesno("Nhận file", "Bạn vừa nhận được 1 file. Bạn có muốn mở lên không?")
            if confirm:
                self.plain_text.delete(0.0, END)
                self.cipher_text.delete(0.0, END)
                self.cipher_text.insert(0.0, msg)


    def send_file(self):
        plain_text = self.plain_text.get(0.0, END)[:-1]  # bo 1 ky tu \n cuoi cung
        cipher_key = self.cipher_key.get()
        if len(cipher_key) == 0:
            mb.showerror("Lỗi", "Vui lòng nhập cipher key")
            return
        if len(plain_text) == 0:
            mb.showerror("Lỗi", "Vui lòng nhập plain text")
            return
        aes_type = self.aes_type.get()
        aes = AESManager(int(aes_type[4:]))
        cipher_text = aes.encrypt(cipher_key, plain_text)
        client.send(cipher_text.encode("utf-8"))


if __name__ == '__main__':
    gui = GUI()
    gui.mainloop()
