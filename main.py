from tkinter import *
from tkinter import messagebox
import base64

FONT = ('Verdena', 11, "normal")


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# save notes
def save_and_encrypt_notes():
    title = title_entry.get()
    message = secret_text.get("1.0", END)
    master_secret = master_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            master_entry.delete(0, END)
            secret_text.delete("1.0", END)


# decrypt notes

def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = master_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

# SCREEN
window = Tk()
window.title("Secret Notes")
window.minsize(400, 625)
window.resizable(False, False)
window.config(padx=30, pady=30)
width = 400  # Width
height = 625  # Height
screen_width = window.winfo_screenwidth()  # Width of the screen
screen_height = window.winfo_screenheight()  # Height of the screen
x = (screen_width / 2) - (width / 2)
y = (screen_height / 2) - (height / 2)
window.geometry('%dx%d+%d+%d' % (width, height, x, y))

# IMAGE
image = PhotoImage(file="image.png")
image = image.subsample(5)
img_label = Label(image=image)
img_label.pack()

# LABEL ENTRY TEXT BUTTON
title_label = Label(text="Enter your title", font=FONT, anchor=CENTER)
title_label.pack()
title_entry = Entry(width=40)
title_entry.pack()
secret_label = Label(text="Enter your secret", font=FONT, anchor=CENTER)
secret_label.pack()
secret_text = Text(width=40, height=18)
secret_text.pack()
master_label = Label(text="Enter master key", font=FONT, anchor=CENTER)
master_label.pack()
master_entry = Entry(width=40)
master_entry.pack()
save_button = Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_button.pack()
dec_button = Button(text="Decrypt", command=decrypt_notes)
dec_button.pack()

window.mainloop()
