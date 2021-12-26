import os
from tkinter import *
from tkinter import ttk, filedialog as fd, messagebox as mb
from AESManager import AESManager
from session.Session import Session
import socket
from socket_config import ADDRESS

file_ext = [
    ('Text File', '*.txt'),
    ('All file', '*.*')
]
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to {}:{}".format(*ADDRESS))
client.connect(ADDRESS)
fileUploaded = []


class ListFileBox:
    cur: int

    def __init__(self, root):
        row = ttk.Frame(root)
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        self.listFile = Listbox(root, activestyle=NONE)
        self.listFile.pack(fill=X, pady=5, padx=10)
        self.render_file()
        self.listFile.bind("<<ListboxSelect>>", self.items_selected)

    def render_file(self, files=None):
        if files is None:
            files = []
        self.cur = -1
        self.listFile.delete(0, END)
        for i in range(len(files)):
            self.listFile.insert(END, f"{files[i]['id']}) {files[i]['file_name']}")  # - {files[i]['author']}

    def items_selected(self, event):
        try:
            selected, = self.listFile.curselection()
            # print(str(self.cur) + '->' + str(selected))
            self.cur = selected
        except:
            self.cur = -1


class GUI(Tk):
    listFileBox: ListFileBox
    aesCombo: ttk.Combobox
    passphraseEntry: ttk.Entry
    errorLabel: ttk.Label
    btnUpload: ttk.Button
    btnDownload: ttk.Button
    storePath: str  # Địa chỉ lưu file

    def __init__(self):
        super().__init__()
        self.geometry('500x400')
        self.title('AES File Transfer')
        self.iconbitmap('icon.ico')
        self.listFileBox = None
        self.setup_gui()
        self.session = Session(client)
        self.session.setCallback(self.handle_command)
        self.session.start()
        self.session.send_command("load_file", "")
        self.storePath = None

    def setup_gui(self):
        row = ttk.Frame(self)
        lbl = ttk.Label(row, text="AES SEND FILE", anchor='w', font=("JetBrains Mono", 10))
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.config(anchor=N)
        lbl.pack()

        row = ttk.Frame(self)
        lbl = ttk.Label(row, width=16, text="Passphrase: ", anchor='nw')
        col = ttk.Frame(row)
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        lbl.pack(side=LEFT)
        col.pack(fill=X)
        entry = ttk.Entry(col)
        self.aesCombo = ttk.Combobox(col, width=10, state='readonly',
                                     values=['AES-128', 'AES-192', 'AES-256'])
        entry.configure(font=("JetBrains Mono", 10))
        entry.insert(0, "1" * 16)
        entry.bind("<KeyRelease>", self.passphrase_change)
        self.passphraseEntry = entry
        self.aesCombo.current(0)
        self.aesCombo.configure(font=("JetBrains Mono", 10))
        self.aesCombo.pack(side=RIGHT, padx=5)
        entry.pack(side=LEFT, expand=True, fill=X)
        lbl = ttk.Label(row, text="", font=("JetBrains Mono", 10), foreground="#ff4d4f")
        self.errorLabel = lbl
        lbl.pack(side=LEFT)

        self.listFileBox = ListFileBox(self)
        self.listFileBox.render_file(fileUploaded)

        row = Frame(self)
        row.pack(side=BOTTOM, fill=X, padx=15, pady=15)
        row.columnconfigure(0, weight=1)
        row.columnconfigure(1, weight=1)
        self.btnUpload = ttk.Button(row, text="Upload File", command=self.upload_file)
        self.btnUpload.grid(row=0, column=0)
        self.btnDownload = ttk.Button(row, text="Download file", command=self.download_file)
        self.btnDownload.grid(row=0, column=1)

    def upload_file(self, *args):
        file_path = fd.askopenfilename(title="Chọn file muốn gửi", defaultextension=file_ext, filetypes=file_ext)
        if not file_path:
            return
        if not os.path.exists(file_path):
            mb.showerror("Lỗi đọc file", "Đường dẫn không tồn tại")
            return
        _, file_name = os.path.split(file_path)
        self.session.send_command("upload", file_name)
        with open(file_path, "r") as fp:
            file_content = fp.read()

        aesType = self.aesCombo.get()
        aesType = int(aesType[4:])
        passphrase = self.passphraseEntry.get()
        aes = AESManager(aesType)
        err = aes.valid_cipher_key(passphrase)
        if err is not None:
            mb.showerror("Lỗi", err)
            return
        try:
            fileEncrypted = aes.encrypt(passphrase, file_content)
            self.session.send_command("upload_content", fileEncrypted)
        except:
            mb.showerror("Lỗi", "Có lỗi xảy ra")
        return

    def download_file(self, *args):
        cur = self.listFileBox.cur
        if cur == -1:
            mb.showinfo("Có lỗi xảy ra", "Vui lòng chọn file muốn tải về")
            return
        if cur >= len(fileUploaded):
            mb.showerror("Lỗi", "File bạn chọn không hợp lệ")
            return
        if self.storePath is not None:
            mb.showerror("Lỗi", "Bạn đang download 1 file khác. Vui lòng đợi")
            return
        fileToDownload = fileUploaded[cur]

        file_path = fd.asksaveasfilename(title="Chọn nơi lưu file", defaultextension=file_ext,\
                                       filetypes=file_ext, initialfile=fileToDownload["file_name"])
        if not file_path:
            return
        self.storePath = file_path
        self.session.send_command("download", str(fileToDownload["id"]))

    def passphrase_change(self, event):
        aesType = self.aesCombo.get()
        aesType = int(aesType[4:])
        passphrase_len = aesType // 8
        passphrase = self.passphraseEntry.get()
        if len(passphrase) < passphrase_len:
            self.errorLabel.configure(text=f"Passphrase ngắn hơn {passphrase_len} ký tự")
            self.btnUpload['state'] = DISABLED
            self.btnDownload['state'] = DISABLED
            return
        if len(passphrase) > passphrase_len:
            self.errorLabel.configure(text=f"Passphrase dài quá {passphrase_len} ký tự")
            self.btnUpload['state'] = DISABLED
            self.btnDownload['state'] = DISABLED
            return

        self.errorLabel.configure(text="")
        self.btnUpload['state'] = NORMAL
        self.btnDownload['state'] = NORMAL

    def handle_command(self, _, command, message):
        if command == 'error':
            mb.showerror("Có lỗi xảy ra", message)
            return
        if command == 'info':
            mb.showinfo("Thông báo", message)
            return
        if command == 'new_file':
            # Khi có file mới server sẽ gửi thông báo đến các máy khác
            # Load vào
            newFile = self.session.decode_json(message)
            print(newFile)
            fileUploaded.insert(0, newFile)
            self.listFileBox.render_file(fileUploaded)
            return
        if command == 'load_file':
            # Khi server gửi thông tin các file trước đó
            fileReceive = self.session.decode_json(message)
            fileUploaded.clear()
            for i in range(len(fileReceive)):
                fileUploaded.insert(0, fileReceive[i])
            self.listFileBox.render_file(fileUploaded)
        if command == 'download':
            if self.storePath is None:
                return
            fileContent = message
            aesType = self.aesCombo.get()
            aesType = int(aesType[4:])
            passphrase = self.passphraseEntry.get()
            aes = AESManager(aesType)
            err = aes.valid_cipher_key(passphrase)
            if err is not None:
                mb.showerror("Lỗi", err)
                return
            try:
                fileDecrypted = aes.decrypt(passphrase, fileContent)
                with open(self.storePath, "w+") as fp:
                    fp.write(fileDecrypted)

                self.storePath = None
            except:
                mb.showerror("Lỗi", "Có lỗi xảy ra")
                self.storePath = None
                return

            mb.showinfo("Thông báo", "Tải về thành công")
            return
        print(command, message)


if __name__ == '__main__':
    gui = GUI()
    gui.mainloop()
