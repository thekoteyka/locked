from cryptography.fernet import Fernet
from tkinter import *
import os, sys

FILE = os.path.basename(sys.argv[0])
IMAGE_FORMATES = ['jpeg']
refuseBlocking = False

def make_key():
    key = str(passwordVar.get())
    key = (key * 44)[:43] + '='
    return key

def encrypt_data(text:str, type=None): 
    if not type == 'bytes':
        text = text.encode()
    

    cipher_key = make_key()
    try:  cipher = Fernet(cipher_key)
    except:
        printuwu('passwrd err')
        return

    encrypted_text = cipher.encrypt(text)

    return encrypted_text.decode('utf-8')

def decrypt_data(text, type=None):
    cipher_key = make_key()
    try:  cipher = Fernet(cipher_key)
    except:
        return
        
    if type == 'bytes':
        try:
            decrypted_text = cipher.decrypt(text)
        except:
            printuwu('fatal, pls tell me error code:\ndecrypt_data:if-type=bytes', color='orange')
            return 0
    else:
        try:
            decrypted_text = cipher.decrypt(text).decode('utf-8')
        except:
            printuwu('fatal, pls tell me error code:\ndecrypt_data:if-type=else',color='orange')
            return 0

    decrypted_text = cipher.decrypt(text)
    return decrypted_text

def isLocked(filename):
    with open(filename, 'r') as f:
        data = f.read()
        if data[:4] == 'gAAA':
            return True
        return False

def getFileFormat(filename:str):
    dotindex = filename.index('.')
    return filename[dotindex+1:]

def lockImage(filename:str):
    with open(filename, 'rb') as f:
        data = f.read()
        encrypted_data = encrypt_data(data, 'bytes')

    with open(filename, 'w') as f:
        f.write(encrypted_data)
        printuwu('successful')

def unlockImage(filename:str):
    with open(filename, 'r') as f:
        data = f.read()
        decrypted_data = decrypt_data(data, type='bytes')
        if decrypted_data is None:
            printuwu('incorrect passwrd')
            return
        elif decrypted_data == 0:
            return

    with open(filename, 'wb') as f:
        f.write(decrypted_data)
        printuwu('successful')

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
    
    if getFileFormat(filename) in IMAGE_FORMATES:
        lockImage(filename)
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
    
    if getFileFormat(filename) in IMAGE_FORMATES:
        unlockImage(filename)
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
        elif decrypted_data == 0:
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

def showHelp(e=None):
    lockedLabel.configure(text='check terminal')
    print('''\nlocked~
==Блокировка файлов==
Заблокировать: введи имя файла и пароль, нажми lock
Разблокировать: введи имя файла и пароль, нажми unlock
          
==Цвета==
          
name:
    лайм - всё хорошо
    красный - неверное имя файла
    фиолетовый - нельзя блокировать сам locked~

passwrd:
    лайм - отличный пароль
    оранжевый - хороший пароль
    зелёный - не очень надёжно, но ограничений на длинну пароля нет
          
          
!Если забыть пароль, то разблокировать будет невозможно (наверное)''')

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

def updPasswordEntryColor(*args):
    password = passwordVar.get()

    lenght = len(password)

    if lenght <= 3:
        passwordEntry.configure(fg='green')
    elif lenght <= 7:
        passwordEntry.configure(fg='orange')
    else:
        passwordEntry.configure(fg='lime')

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

passwordEntry = Entry(root, textvariable=passwordVar, fg='red')
passwordEntry.place(x=60, y=90)
passwordVar.trace_add('write', updPasswordEntryColor)

OutputLabel = Label(root, text='')
OutputLabel.place(x=5, y=160)


b = Label(root, text='?', relief='flat')
b.place(x=281, y=174)
b.bind("<Button-1>", showHelp)
b.bind("<Enter>", lambda e: lockedLabel.configure(text='click to show help'))
b.bind("<Leave>", lambda e: lockedLabel.configure(text='locked~'))

root.mainloop()