from cryptography.fernet import Fernet
from tkinter import *
import os, sys

FILE = os.path.basename(sys.argv[0])
refuseBlocking = False

def make_key():
    key = str(passwordVar.get())
    key = (key * 44)[:43] + '='
    return key

def encrypt_data(text): 
    text = text.encode()
    

    cipher_key = make_key()
    try:  cipher = Fernet(cipher_key)
    except:
        printuwu('passwrd err')
        return

    encrypted_text = cipher.encrypt(text)

    return encrypted_text.decode('utf-8')

def decrypt_data(text):

    cipher_key = make_key()
    try:  cipher = Fernet(cipher_key)
    except:
        return
        
    
    try:  decrypted_text = cipher.decrypt(text).decode('utf-8')
    except:
        return
    
    return decrypted_text

def isLocked(filename):
    with open(filename, 'r') as f:
        data = f.read()
        if data[:4] == 'gAAA':
            return True
        return False

def lockFile():
    filename = filenameVar.get()

    if refuseBlocking:
        printuwu('blocking is currently unavailable', color='#9933CC')
        return

    if not passwordVar.get():
        printuwu('enter passwrd')
        return
    
    try:
        open(filename, 'r')
    except:
        printuwu('file not found')
        return
    
    if isLocked(filename):
        printuwu(f'the {filename} has already been locked')
        return

    
    with open(filename, 'r') as f:
        data = f.read()
        encrypted_data = encrypt_data(data)

    with open(filename, 'w') as f:
        f.write(encrypted_data)
        printuwu('successful')

def unlockFile():
    filename = filenameVar.get()

    try:
        open(filename, 'r')
    except:
        printuwu('file not found')
        return

    if not isLocked(filename):
        printuwu(f'the {filename} has already been unlocked')
        return

    with open(filename, 'r') as f:
        data = f.read()
        decrypted_data = decrypt_data(data)
        if decrypted_data is None:
            printuwu('incorrect passwrd')
            return

    with open(filename, 'w') as f:
        f.write(decrypted_data)
        printuwu('successful')

def printuwu(text, color:str=None):
    OutputLabel.configure(text=text)
    if color:
        OutputLabel.configure(fg=color)
    else:
        OutputLabel.configure(fg='systemTextColor')

def showHelp():
    ... #TODO

def updFilenameEntryColor(*args):
    global refuseBlocking
    filename = filenameVar.get()
    

    if filename == FILE:
        filenameEntry.configure(fg='#9933CC')
        printuwu('locked cant lock itself', color='#9933CC')
        refuseBlocking = True
        return

    try:
        open(filename)
    except:
        filenameEntry.configure(fg='red')
    else:
        filenameEntry.configure(fg='lime')
    finally:
        refuseBlocking = False

root = Tk()
root.geometry('300x200')
root.title(' ')
filenameVar = StringVar(root)
passwordVar = StringVar(root)

lockedLabel = Label(root, text='locked~')
lockedLabel.pack()

Button(root, text='lock', command=lockFile).place(x=5, y=120)
Button(root, text='unlock', command=unlockFile).place(x=220, y=120)

Label(root, text='name').place(x=5, y=60)
Label(root, text='passwrd').place(x=5, y=90)

filenameEntry = Entry(root, textvariable=filenameVar)
filenameEntry.place(x=60, y=60)
filenameVar.trace_add('write', updFilenameEntryColor)

Entry(root, textvariable=passwordVar, fg='red').place(x=60, y=90)

OutputLabel = Label(root, text='')
OutputLabel.place(x=5, y=160)


b = Label(root, text='?', relief='flat')
b.place(x=271, y=174)
b.bind("<Button-1>",lambda x: print(2))
b.bind("<Enter>",lambda x: lockedLabel.configure(text='click to show help'))
b.bind("<Leave>",lambda x: lockedLabel.configure(text='locked~'))

root.mainloop()