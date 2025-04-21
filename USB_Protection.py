#import tkinter as tk
from tkinter import filedialog, messagebox
import os
import json
import hashlib
import psutil
import time
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from googleapiclient.errors import HttpError
import io
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import customtkinter

import gzip
import shutil
import os.path
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

class ResultWindow:
    def __init__(self, message):
        self.root = customtkinter.CTkToplevel()
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("green")
        self.root.title("Result")
        self.root.geometry("444x133")

        self.frame = customtkinter.CTkFrame(master=self.root)
        self.frame.pack(pady=10)

        font_style = ("Courier New", 16)
        self.label = customtkinter.CTkLabel(master=self.frame, text=message, font=font_style)
        self.label.pack(pady=10,padx=10)

        self.button = customtkinter.CTkButton(master=self.frame, text="OK", command=self.close_window)
        self.button.pack(pady=10,padx=10)

    def close_window(self):
        self.root.destroy()



class USBManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SFORM")
        self.root.geometry("550x820")

        self.create_widgets()

        self.key = None
        self.password_hash = None
        self.load_password()

    def create_widgets(self):
        font_style = ("Courier New", 16)

        self.frame = customtkinter.CTkFrame(master=self.root)
        self.frame.pack(pady=70,padx=50)

        self.usb_drive_label = customtkinter.CTkLabel(master=self.frame, text="     Check for USB     ", pady=35, font=font_style)
        self.usb_drive_label.pack(pady=5,padx=30)

        self.check_usb_button = customtkinter.CTkButton(master=self.frame, text="Check USB", command=self.check_usb_drive, font=font_style)
        self.check_usb_button.pack(pady=15,padx=30)

        usb_lable = customtkinter.CTkLabel(master=self.frame,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=20)

        self.usb_buttons = []  # Keep track of USB buttons

        # Error label for displaying error messages
        self.error_label = customtkinter.CTkLabel(master=self.frame, text="", font=("Courier New", 16))

        self.encrypt_buttons = []
        self.decrypt_buttons = []

    def load_password(self):
        creds = None

        if os.path.exists("token.pickle"):
            with open("token.pickle", "rb") as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    {
                        "web": {
                            "client_id": "1094011912503-kkaciv5c24gtb26s0ann81n91ul1nia9.apps.googleusercontent.com",
                            "project_id": "security-974dd",
                            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                            "token_uri": "https://oauth2.googleapis.com/token",
                            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                            "client_secret": "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",
                            "redirect_uris": ["http://localhost:8080/"]
                        }
                    },
                    scopes=SCOPES
                )

                creds = flow.run_local_server(port=8080)
                with open("token.pickle", "wb") as token:
                    pickle.dump(creds, token)

        service = build("drive", "v3", credentials=creds)
        print("Google Drive service object built.")
        print("Loading password...")

        results = (
            service.files()
            .list(q="name='password.json'", spaces="drive", fields="files(id, name)")
            .execute()
        )

        items = results.get("files", [])
        if not items:
            print("No password.json found.")
        else:
            print("Downloading password.json...")
            file_id = items[0]["id"]
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            fh.seek(0)
            print("Loading password.json...")
            data = json.load(fh)
            self.password_hash = data.get("password_hash")

    def save_password(self, password):
        creds = None
        if os.path.exists("token.pickle"):
            with open("token.pickle", "rb") as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())

        service = build("drive", "v3", credentials=creds)

        print("Creating password hash...")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        data = {"password_hash": password_hash}
        file_metadata = {"name": "password.json"}

        print("Uploading password.json...")
        media = MediaIoBaseUpload(
            io.BytesIO(json.dumps(data).encode()), mimetype="application/json"
        )

        file = (
            service.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )

        print("File ID: %s" % file.get("id"))

    def check_usb_drive(self):
        usb_drives = self.get_available_usb_drives()

        if usb_drives:
            selected_drive = self.choose_usb_drive(usb_drives)
            if selected_drive:
                self.open_password_field(selected_drive)
                #self.frame.destroy()
        else:
            self.show_error_message("No USB drive detected")
        
    def choose_usb_drive(self, usb_drives ):

        font_style = ("Courier New", 16)

        usb_lable = customtkinter.CTkLabel(self.root,text="  ",pady=1,font=font_style)
        usb_lable.pack(pady=15,padx=25)

        self.frame1 = customtkinter.CTkFrame(master=self.root)
        self.frame1.pack(pady=1,padx=20)
        # Create buttons for each removable USB drive
        usb_lable = customtkinter.CTkLabel(master=self.frame1,text="Select the USB you want",pady=5,font=font_style)
        usb_lable.pack(pady=20,padx=20)

        for drive in usb_drives:

            usb_button = customtkinter.CTkButton(master=self.frame1, text=drive, command=lambda d=drive: self.open_password_field(d), font=font_style)
            usb_button.pack(side=customtkinter.TOP,pady=10,padx=20)
            self.usb_buttons.append(usb_button)

        usb_lable = customtkinter.CTkLabel(master=self.frame1,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=20)

    def open_password_field(self, selected_drive):
        self.frame1.destroy()
        self.usb_drive_label.pack_forget()
        self.check_usb_button.pack_forget()
        self.frame.pack_forget()
        self.selected_drive = selected_drive  # Store the selected drive

        PasswordEntryWindow(self.root, self.confirm_password)
        
    def confirm_password(self, password):

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if self.password_hash is None:
            self.password_hash = password_hash
            self.save_password(password)
            self.hide_error_message()
            self.open_main_window()
        elif password_hash == self.password_hash:
            self.hide_error_message()
            self.open_main_window()
        else:
            messagebox.showerror("Incorrect Password", "Please enter a password.")
            self.open_password_field(self)


    def reset_password(self, new_password):
        self.password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        self.save_password(new_password)
        self.hide_error_message()

    def derive_key(self, password):
        salt = b'salt_'  # Can be any value
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def open_main_window(self):
        for usb_button in self.usb_buttons:
            usb_button.pack_forget()
        font_style = ("Courier New", 16)

        self.frame1 = customtkinter.CTkFrame(master=self.root)
        self.frame1.pack(pady=1,padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame1,text=" ",pady=1,font=font_style)
        usb_lable.pack(pady=1,padx=25)

        encrypt_button = customtkinter.CTkButton(master=self.frame1, text="       Encrypt All Files       ", command=lambda: self.encrypt_all_files(self.selected_drive), font=font_style)
        encrypt_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        decrypt_button = customtkinter.CTkButton(master=self.frame1, text="       Decrypt All Files       ", command=lambda: self.decrypt_all_files(self.selected_drive), font=font_style)
        decrypt_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        compress_encrypt_button = customtkinter.CTkButton(master=self.frame1, text="  Compress & Encrypt All Files ", command=lambda: self.compress_and_encrypt_all_files(self.selected_drive), font=font_style)
        compress_encrypt_button.pack(side=customtkinter.TOP, pady=8, padx=25)

        decompress_decrypt_button = customtkinter.CTkButton(master=self.frame1, text=" Decompress & Decrypt All Files", command=lambda: self.decompress_and_decrypt_all_files(self.selected_drive), font=font_style)
        decompress_decrypt_button.pack(side=customtkinter.TOP, pady=8, padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame1,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=25)

        self.frame2 = customtkinter.CTkFrame(master=self.root)
        self.frame2.pack(pady=30,padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame2, text="",text_color= "light blue", pady=5, font=font_style)
        usb_lable.pack(pady=1, padx=25)

        select_files_button = customtkinter.CTkButton(master=self.frame2, text="    Select Files to Encrypt    ", command=self.select_files_to_encrypt, font=font_style)
        select_files_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        select_files_decrypt_button = customtkinter.CTkButton(master=self.frame2, text="    Select Files to Decrypt    ", command=self.select_files_to_decrypt, font=font_style)
        select_files_decrypt_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        compress_encrypted_button = customtkinter.CTkButton(master=self.frame2, text="    Select Files to Compress   ", command=self.compress_files, font=font_style)
        compress_encrypted_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        decompress_encrypted_button = customtkinter.CTkButton(master=self.frame2, text="   Select Files to Decompress  ", command=self.decompress_files, font=font_style)
        decompress_encrypted_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame2,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=25)

        self.frame3 = customtkinter.CTkFrame(master=self.root)
        self.frame3.pack(pady=5,padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame3, text="",text_color= "light blue" ,pady=1, font=font_style)
        usb_lable.pack(pady=1, padx=25)

        upload_file_button = customtkinter.CTkButton(master=self.frame3, text="     Upload File to Drive      ", command=self.upload_file_to_drive, font=font_style)
        upload_file_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        change_password_button = customtkinter.CTkButton(master=self.frame3, text="        Change Password        ", command=self.change_password, font=font_style)
        change_password_button.pack(side=customtkinter.TOP, pady=8,padx=25)

        usb_lable = customtkinter.CTkLabel(master=self.frame3,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=25)

    def change_password(self):
        NewPasswordEntryWindow(self.root, self.reset_password)

    def encrypt_all_files(self, selected_drive):
        if selected_drive:
            key = self.derive_key(self.password_hash)
            for root, dirs, files in os.walk(selected_drive):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path, key)
            self.show_result_message("All files encrypted successfully.")

    def select_files_to_encrypt(self):
        files = filedialog.askopenfilenames()
        if files:
            key = self.derive_key(self.password_hash)
            for file in files:
                self.encrypt_file(file, key)
            self.show_result_message("Selected files encrypted successfully.")

    def encrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(file_path + '.enc', 'wb') as f:
            f.write(iv + ciphertext)
        os.remove(file_path)

    def decrypt_all_files(self, selected_drive):
        if selected_drive:
            key = self.derive_key(self.password_hash)
            for root, dirs, files in os.walk(selected_drive):
                for file in files:
                    if file.endswith('.enc'):
                        file_path = os.path.join(root, file)
                        self.decrypt_file(file_path, key)
            self.show_result_message("All files decrypted successfully.")

    def select_files_to_decrypt(self):
        files = filedialog.askopenfilenames()
        if files:
            key = self.derive_key(self.password_hash)
            for file in files:
                if file.endswith('.enc'):
                    self.decrypt_file(file, key)
            self.show_result_message("Selected files decrypted successfully.")

    def decrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            ciphertext = f.read()
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file_path[:-4], 'wb') as f:
            f.write(plaintext)
        os.remove(file_path)

    def compress_files(self):
        start_time = time.time()
        files = filedialog.askopenfilenames()
        if files:
            for file in files:
                self.compress_file(file)
            end_time = time.time()
            duration = end_time - start_time
            self.show_result_message("Files compressed successfully.")

    def compress_file(self, file_path):
        with open(file_path, 'rb') as f_in:
            with gzip.open(file_path + '.gz', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(file_path)

    def decompress_files(self):
        files = filedialog.askopenfilenames()
        if files:
            for file in files:
                self.decompress_file(file)
            self.show_result_message("Files decompressed successfully.")

    def decompress_file(self, file_path):
        with gzip.open(file_path, 'rb') as f_in:
            with open(file_path[:-3], 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(file_path)

    def compress_and_encrypt_all_files(self, selected_drive):
        if selected_drive:
            key = self.derive_key(self.password_hash)
            for root, dirs, files in os.walk(selected_drive):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.compress_file(file_path)  # First compress the file
                    self.encrypt_file(file_path + '.gz', key)  # Then encrypt the compressed file
            self.show_result_message("All files compressed and \nencrypted successfully.")

    def decompress_and_decrypt_all_files(self, selected_drive):
        if selected_drive:
            key = self.derive_key(self.password_hash)
            for root, dirs, files in os.walk(selected_drive):
                for file in files:
                    if file.endswith('.enc'):
                        file_path = os.path.join(root, file)
                        self.decrypt_file(file_path, key)  # First decrypt the file
                        self.decompress_file(file_path[:-4])  # Then decompress the decrypted file
            self.show_result_message("All files decompressed and \ndecrypted successfully.")

    def upload_file_to_drive(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                creds = None
                if os.path.exists("token.pickle"):
                    with open("token.pickle", "rb") as token:
                        creds = pickle.load(token)

                if not creds or not creds.valid:
                    if creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                    else:
                        flow = InstalledAppFlow.from_client_secrets_file(
                            "credentials.json", SCOPES)
                        creds = flow.run_local_server(port=0)
                        with open("token.pickle", "wb") as token:
                            pickle.dump(creds, token)

                service = build("drive", "v3", credentials=creds)
                file_metadata = {'name': os.path.basename(file_path)}
                media = MediaIoBaseUpload(io.FileIO(file_path, 'rb'), mimetype='application/octet-stream')

                file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
                self.show_result_message(f"File uploaded successfully,File ID:\n {file.get('id')}")
            except Exception as e:
                self.show_result_message(f"An error occurred: {str(e)}")

    def get_available_usb_drives(self):
        if os.name == "posix":
            drives = [d.mountpoint for d in psutil.disk_partitions() if "removable" in d.opts]
        elif os.name == "nt":
            drives = [d.device for d in psutil.disk_partitions() if "removable" in d.opts]
            #self.frame.destroy()
        else:
            raise RuntimeError("Unsupported operating system")
        return drives

    def show_error_message(self, message):
        self.error_label.configure(text=message)
        self.error_label.pack(pady=10,padx=50)

    def hide_error_message(self):
        self.error_label.pack_forget()

    def show_result_message(self, message):
        ResultWindow(message)

class PasswordEntryWindow:
    def __init__(self, root, confirm_callback):
        self.root = customtkinter.CTkToplevel(root)
        self.root.title("Enter Password")
        self.root.geometry("350x230")

        font_style = ("Courier New", 16)

        self.frame = customtkinter.CTkFrame(master=self.root)
        self.frame.pack(pady=20,padx=40)

        self.confirm_callback = confirm_callback

        self.password_label = customtkinter.CTkLabel(master=self.frame, text="Enter password", pady=5, font=font_style)
        self.password_label.pack(pady=5,padx=20)

        self.password_entry = customtkinter.CTkEntry(master=self.frame, show="*", font=font_style)
        self.password_entry.pack(pady=5,padx=20)

        self.confirm_button = customtkinter.CTkButton(master=self.frame, text="Confirm", command=self.confirm_password, font=font_style)
        self.confirm_button.pack(pady=15,padx=20)

        usb_lable = customtkinter.CTkLabel(master=self.frame,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=20)

    def confirm_password(self):
        password = self.password_entry.get()

        if password:
            self.confirm_callback(password)
            self.root.destroy()
        else:
            messagebox.showerror("Empty Password", "Please enter a password.")

class NewPasswordEntryWindow:
    def __init__(self, root, reset_password_callback):
        self.root = customtkinter.CTkToplevel(root)
        self.root.title("Enter New Password")
        self.root.geometry("350x300")

        font_style = ("Courier New", 16)

        self.frame = customtkinter.CTkFrame(master=self.root)
        self.frame.pack(pady=20,padx=20)

        self.reset_password_callback = reset_password_callback



        self.password_label = customtkinter.CTkLabel(master=self.frame, text="Enter new password:", pady=5, font=font_style)
        self.password_label.pack(pady=5,padx=20)

        self.password_entry = customtkinter.CTkEntry(master=self.frame, show="*", font=font_style)
        self.password_entry.pack(pady=5,padx=20)

        self.confirm_password_label = customtkinter.CTkLabel(master=self.frame, text="Confirm password:", pady=5, font=font_style)
        self.confirm_password_label.pack(pady=5,padx=20)

        self.confirm_password_entry = customtkinter.CTkEntry(master=self.frame, show="*", font=font_style)
        self.confirm_password_entry.pack(pady=5,padx=20)

        self.confirm_button = customtkinter.CTkButton(master=self.frame, text="Confirm", command=self.confirm_password, font=font_style)
        self.confirm_button.pack(pady=15,padx=20)

        usb_lable = customtkinter.CTkLabel(master=self.frame,text="  ",pady=5,font=font_style)
        usb_lable.pack(pady=1,padx=20)

    def confirm_password(self):
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if password and confirm_password:
            if password == confirm_password:
                self.reset_password_callback(password)
                self.root.destroy()
            else:
                messagebox.showerror("Password Mismatch", "Passwords do not match")
        else:
            messagebox.showerror("Empty Password", "Please enter a password")

if __name__ == "__main__":
    root = customtkinter.CTk()
    usb_manager = USBManager(root)
    root.mainloop()
