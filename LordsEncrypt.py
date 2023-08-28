import ctypes
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import os,shutil,sys,re
import tkinter as tk

from tkinter import filedialog, ttk

#GUI#####################################################################
def close_window():
    window.destroy()  # Close the main window
    if root.winfo_exists():  # Check if root window still exists
        root.destroy()  # Close the root window
    sys.exit()  # Exit the Python process

initial_x = None
initial_y = None

def on_title_bar_press(event):
    global initial_x, initial_y
    initial_x = event.x
    initial_y = event.y

def on_title_bar_drag(event):
    global initial_x, initial_y
    window_x = window.winfo_x() + (event.x - initial_x)
    window_y = window.winfo_y() + (event.y - initial_y)
    window.geometry(f"+{window_x}+{window_y}")

def show_ghost_text(event):
    if password_entry.get() == "Password":
        password_entry.delete(0, tk.END)
        password_entry.config(show="*")

def hide_ghost_text(event):
    if not password_entry.get():
        password_entry.config(show="")
        password_entry.insert(0, "Password")

test_static_salt = b'\xdf-x|D\xb8R\x14pgB\xda\x99\x97~\xa2Eg\x12\xab\xcf\x10r\x1es\xd1Zj\x90\x8akZ'
what_is_selected = "nothing"

file_name = ""
file_paths = ""
def choose_file():
    global file_paths
    global what_is_selected
    file_paths = filedialog.askopenfilenames(title="Select File")
    if file_paths:
        if len(file_paths) == 1:
            file_path_label.config(text="Selected File: " + file_paths[0])
            what_is_selected = "file"
            return
        
        file_path_label.config(text="Selected Files: " + "Multiple")
        what_is_selected = "file"
    else:
        file_error_label.config(text="No file selected", fg="dark red")

folder_name = ""

def choose_folder():
    
    global folder_path
    global folder_name
    global zip_file_name
    global what_is_selected
    
    folder_path = filedialog.askdirectory()

    if folder_path:
        file_path_label.config(text="Selected Folder: " + folder_path)
        what_is_selected = "folder"

        folder_name = os.path.basename(folder_path)
        zip_file_name = folder_name + ".zip"
        

    else:
        file_error_label.config(text="No folder selected",fg="dark red")

def zip_folder():
    shutil.make_archive(folder_path, "zip", folder_path)

def encrypt_file():
    
    global file_paths
    global folder_path
    global file_name
    chunk_size = 4096
    file_in_bytes = b''

    password = password_entry.get()
    re.sub('\W+','',password).strip()

    if not file_paths and not folder_name:
        file_error_label.configure(text="File not selected or supported: " + file_name, fg="dark red")
        return
    if password == "Password" or "" or not password:
        file_error_label.configure(text="Choose password !", fg="dark red")
        return
    


    err = "false"
    if what_is_selected == "file":
        i = 0
        for file_path in file_paths:
            i = i + 1
            file_name = os.path.basename(file_path)
            print(file_name)
            if file_name.startswith("$"):
                err = "true"
                file_error_label.configure(text="The file has already been locked !", fg="dark red")
                
            else:

                with open(file_path,"rb") as file:
                    while True:
                        chunk = file.read(chunk_size)
                        if chunk == b"":
                            break
                        file_in_bytes += chunk
                file.close()
            
                key = PBKDF2(password,test_static_salt, dkLen=32)

                cipher = AES.new(key, AES.MODE_CBC)
                ciphered_data = cipher.encrypt(pad(file_in_bytes, AES.block_size))

                locked_file_name = "$" + file_name

                locked_file_path = os.path.dirname(os.path.abspath(file_path))
                locked_file_path += '\\' + locked_file_name

                with open(locked_file_path,"wb") as file:
                    file.write(cipher.iv)
                    file.write(ciphered_data)
                file.close()

                # double check
                with open(locked_file_path,"rb") as file:
                    iv = file.read(16)
                    decrypt_data = file.read()
                file.close()

                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                original_file = unpad(cipher.decrypt(decrypt_data), AES.block_size)
                
                if original_file == file_in_bytes:
                    os.remove(file_path)
                    file_error_label.configure(text="File encrypted! (" + str(i) + ")", fg="dark green")

                if err == "true":
                    file_error_label.configure(text="Files encrypted! (" + str(i) + ")" + " some skipped (already encrypted)", fg="dark green")
        i = 0

    if what_is_selected == "folder":
        global zip_file_name
        zip_folder()

        zipped_folder_path = os.path.dirname(folder_path) + "\\" + zip_file_name
        
        with open(zipped_folder_path,"rb") as file:
            while True:
                chunk = file.read(chunk_size)
                if chunk == b"":
                    break
                file_in_bytes += chunk
        file.close()

        key = PBKDF2(password,test_static_salt, dkLen=32)

        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(file_in_bytes, AES.block_size))

        locked_zipped_folder_path = os.path.dirname(folder_path) + "\\" + "$" + zip_file_name

        with open(locked_zipped_folder_path,"wb") as file:
            file.write(cipher.iv)
            file.write(ciphered_data)
        file.close()
        os.remove(zipped_folder_path)
        shutil.rmtree(folder_path)

        file_error_label.configure(text="Folder encrypted!", fg="dark green")   
        del file_in_bytes,chunk,key,cipher,ciphered_data,zipped_folder_path,locked_zipped_folder_path

        return

    
    
decrypt_attempts = 0
def decrypt_file():
    global decrypt_attempts
    global file_name
    global file_paths
    password = password_entry.get()
    err = "false"
    for file_path in file_paths:

        file_name = os.path.basename(file_path)

        if not file_name.startswith("$"):
            err = "true"

        else:

            with open(file_path,"rb") as file:
                iv = file.read(16)
                decrypt_data = file.read()
            file.close()
        
            key = PBKDF2(password,test_static_salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            try:
                original_file = unpad(cipher.decrypt(decrypt_data), AES.block_size)
                file_name = file_name[1:]
                unlocked_file_path = os.path.dirname(file_path) + "\\" + file_name
                with open(unlocked_file_path,"wb") as file:
                    file.write(original_file)
                file.close()
                
                if file_name.endswith(".zip"):
                    
                    unzipped_folder_name = unlocked_file_path[:-4]
                    os.makedirs(unzipped_folder_name, exist_ok=True)
                    shutil.unpack_archive(unlocked_file_path, unzipped_folder_name)
                    os.remove(unlocked_file_path)

                os.remove(file_path)
                decrypt_attempts = 0 
            except:
                file_error_label.configure(text="Bad password", fg="dark red")
                decrypt_attempts += 1

                if decrypt_attempts >= 3:
                    file_error_label.configure(text="Too many attempts", fg="dark red")
                    close_window()
                return
            
        if err == "true":
            file_error_label.configure(text="Files decrypted (some skipped already decrypted)", fg="dark green")
        else:    
            file_error_label.configure(text="Files decrypted", fg="dark green")


# Create a dummy root window
root = tk.Tk()
root.withdraw()

title_bar_font = ("Consolas", 18)
button_font = ("Consolas", 11)

# Create the main window
window = tk.Tk()
window.overrideredirect(False)
window.geometry("650x300")
window.configure(background="#2e2e2e")
window.title("Lord's Encrypt")
try:
    window.iconbitmap("encryption.ico")
except:
    pass

button_frame = tk.Frame(window, bg="#2e2e2e")
button_frame.pack(anchor="nw", padx=10, pady=10)

choose_file_button = tk.Button(button_frame, text="Choose File", bg="gray", fg="white", command=choose_file, font=button_font)
choose_file_button.grid(row=0, column=0, padx=5)

choose_folder_button = tk.Button(button_frame, text="Choose Folder", bg="gray", fg="white", command=choose_folder, font=button_font)
choose_folder_button.grid(row=0, column=1, padx=5)

blank_space = tk.Label(button_frame, bg="#2e2e2e")
blank_space.grid(row=0, column=2, padx=40)  # Add a blank space between buttons

password_entry = tk.Entry(button_frame, show="", font=button_font, width=15)
password_entry.insert(0, "Password")
password_entry.bind("<FocusIn>", show_ghost_text)
password_entry.bind("<FocusOut>", hide_ghost_text)
password_entry.grid(row=0, column=3, padx=5)

encrypt_button = tk.Button(button_frame, text="Encrypt!", bg="dark gray", fg="white", command=encrypt_file, font=button_font)
encrypt_button.grid(row=0, column=4, padx=5)

decrypt_button = tk.Button(button_frame, text="Decrypt!", bg="dark gray", fg="white", command=decrypt_file, font=button_font)
decrypt_button.grid(row=0, column=5, padx=5)

file_path_label = tk.Label(window, text="Selected File: ", font=button_font, fg="dark green", bg="#2e2e2e")
file_path_label.pack(anchor="w", padx=10, pady=(0, 10))

file_error_label = tk.Label(window, text="", font=button_font, fg="dark red", bg="#2e2e2e")
file_error_label.pack(anchor="w", padx=10, pady=(0, 10))

window.protocol("WM_DELETE_WINDOW", close_window)
# Run the main event loop
root.mainloop()

#GUI#####################################################################
