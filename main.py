from cryptography.fernet import Fernet
from tkinter import *
import os, sys

FILE = os.path.basename(sys.argv[0])  # имя файла (locked)
NON_TEXT_FORMATS = ['jpeg', 'mp3', 'mov']  # форматы, для которых будут использоваться методы шифрования байтов
refuseBlocking = False  # заблокировать блокировку файлов




def general_test():
    # данные для тестирования:
    text_file = 'file.py'
    non_text_file = 'p.jpeg'
    password = 'qwerty1234'

    if isLocked(text_file):
        print(f'сначала разблокируй {text_file}')
        exit()
    if isLocked(non_text_file):
        print(f'сначала разблокируй {non_text_file}')
        exit()

    passwordVar.set(password)
    filenameVar.set(text_file)

    try:
        Fernet(make_key())
    except:
        print('ошибка генерации ключа')
        exit()

    lock()

    if not isLocked(text_file):
        print(f'файл {text_file} не зашифровался')
        exit()

    unlock()

    if isLocked(text_file):
        print(f'файл {text_file} не расшифровался')
        exit()
            
    passwordVar.set(password)
    filenameVar.set(non_text_file)

    lock()

    if not isLocked(non_text_file):
        print(f'файл {non_text_file} не зашифровался')
        exit()
        
    unlock()

    if isLocked(non_text_file):
        print(f'файл {non_text_file} не расшифровался')
        exit()

    passwordVar.set('')
    filenameVar.set('')


def make_key() -> str:
    '''
    Создаёт ключ для Fernet
    '''
    key = str(passwordVar.get())
    key = (key * 44)[:43] + '='
    return key

def encrypt_data(text:str, type=None) -> str|None: 
    '''
    Зашифровывает переданный текст, если он в байтах то укажи это в параметре type
    '''
    if not type == 'bytes':  # Если перены не байты, то переводим в них
        text = text.encode()
    

    cipher_key = make_key()  # Генерируем ключ для шифровки
    try:  cipher = Fernet(cipher_key)
    except:
        printuwu('passwrd err')  # В норме не выводится, а перекрывается другим
        return

    encrypted_text = cipher.encrypt(text)  # Шифруем

    return encrypted_text.decode('utf-8')

def decrypt_data(text, type=None) -> str|bytes|None:
    '''
    Расшифровывает переданный текст, если он в байтах то укажи это в параметре type

    return:

    str - засшифрованый текст

    bytes - зашифрованные байты

    None - ошибка ключа/пароля
    '''
    cipher_key = make_key()  # Создаём ключ
    try:  cipher = Fernet(cipher_key)
    except:
        return
        
    if type == 'bytes':
        try:
            decrypted_text = cipher.decrypt(text)  # Если нужны байты, то не переводим из них в str
        except:
            return
    else:
        try:
            decrypted_text = cipher.decrypt(text).decode('utf-8')
        except:
            return 
    
    return decrypted_text


def isLocked(filename:str) -> bool:
    '''
    Возвращает True, если файл заблокирован, или False, если он разблокирован
    '''
    if getFileFormat(filename) in NON_TEXT_FORMATS:  # Если файл не текстовый
        with open(filename, 'rb') as f:
            data = f.read()
            try:  # Если получается преобразовать в utf8, то значит зашифровано
                data = data.decode('utf-8')
                return True
            except:  # Если нет, то расшифровано
                return False
            
    else:
        with open(filename, 'r') as f:
            data = f.read()
            if data[:4] == 'gAAA':  # Если начинается с этих символов, то он зашифрован
                return True
            return False

def getFileFormat(filename:str) -> str:
    '''
    Получить расширение файла (без точки)
    Пример: jpeg
    '''
    dotindex = filename.index('.')
    return filename[dotindex+1:]


def lockNonText(filename:str) -> None:
    '''
    Блокирует файл, не являющийся текстовым
    '''
    with open(filename, 'rb') as f:
        data = f.read()  # Получаем данные из файла
        encrypted_data = encrypt_data(data, 'bytes')  # Зашифровываем их

    with open(filename, 'w') as f:
        f.write(encrypted_data)  # Перезаписываем файл зашифроваными данными
        printuwu('successful')

def unlockNonText(filename:str) -> None:
    '''
    Разблокирует файл, не являющийся текстовым
    '''
    with open(filename, 'r') as f:
        data = f.read()  # Получаем данные из файла
        decrypted_data = decrypt_data(data, type='bytes')  # Расшифровывем полученные данные
        if decrypted_data is None:  # Если decrypt_data вернула 0, значит произошла ошибка пароля
            printuwu('incorrect passwrd')
            return

    with open(filename, 'wb') as f:
        f.write(decrypted_data)
        printuwu('successful')

def lockText(filename:str) -> None:
    '''
    Блокирует текстовый файл
    '''
    with open(filename, 'r') as f:
        data = f.read()  # Получаем данные из файла
        encrypted_data = encrypt_data(data)  # Зашифровываем эти данные

    with open(filename, 'w') as f:
        f.write(encrypted_data)  # Перезаписываем файл с зашифроваными данными
        printuwu('successful')

def unlockText(filename:str) -> None:
    '''
    Разблокирует текстовый файл
    '''
    with open(filename, 'r') as f:
        data = f.read()  # Получаем данные из файла
        decrypted_data = decrypt_data(data)  # Зашифровываем поулченные данные
        if decrypted_data is None:  # Если вернула None, значит ошибка пароля
            printuwu('incorrect passwrd')
            return

    with open(filename, 'w') as f:  # Открываем файл для перезаписи
        f.write(decrypted_data)  # Перезаписываем зашифрованными данными
        printuwu('successful')


def lock() -> None:
    '''
    Блокирует файл, перенаправляя в нужную функцию
    '''
    filename = filenameVar.get()  # Получаем имя файла

    if refuseBlocking:  # Если остановлена блокировка файлов (например когда попытка блокировки этого файла)
        printuwu('blocking is currently unavailable', color='#9933CC')
        return

    if not passwordVar.get():  # Если не введён пароль
        printuwu('enter passwrd')
        return
    
    try:
        open(filename, 'r')
    except:  # Если не найден файл
        printuwu('file not found')
        return
    
    if isLocked(filename):  # Если файл уже заблокирован
        printuwu(f'the {filename} has already been locked')
        return

    if getFileFormat(filename) in NON_TEXT_FORMATS:  # Если файл не текстовый, то перенаправляем в функцию, которая шифрует нетекстовые файлы
        lockNonText(filename)
        return
    else:
        lockText(filename)
    
def unlock() -> None:
    '''
    Разблокирует файл, перенаправляя в нужную функцию
    '''
    filename = filenameVar.get()

    try:
        open(filename, 'r')
    except:  # Если файл не найден
        printuwu('file not found')
        return

    if not isLocked(filename):  # Если файл уже разблокирован (не заблокирован)
        printuwu(f'the {filename} has already been unlocked')
        return
    
    if getFileFormat(filename) in NON_TEXT_FORMATS:  # Если файл не текстовый
        unlockNonText(filename)
    else:
        unlockText(filename)


def printuwu(text, color:str=None) -> None:
    '''
    Выводит текст в специальное место программы слева снизу
    '''
    OutputLabel.configure(text=text)
    if color:
        OutputLabel.configure(fg=color)
    else:
        OutputLabel.configure(fg='systemTextColor')  # Цвет темы в мак ос

def showHelp(e=None) -> None:
    '''
    Показывает справку в терминале
    '''
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

def updFilenameEntryColor(*args) -> None:
    '''
    Изменяет цвет вводимого имени файла в зависимости от условий
    '''
    global refuseBlocking
    filename = filenameVar.get()
    

    if filename == FILE:  # Если ввели этот файл (сам locked)
        filenameEntry.configure(fg='#9933CC')
        printuwu('locked cant lock itself', color='#9933CC')
        refuseBlocking = True  # Останавливаем блокировку файлов, чтобы не заблокировать себя
        return

    try:
        open(filename)  # Пробуем открыть файл
    except:
        filenameEntry.configure(fg='red')  # Если получилось значит файл есть, делаем текст зелёным
    else:
        filenameEntry.configure(fg='lime')  # Если нет, то файла нет, делаем текст красным
    finally:
        refuseBlocking = False  # В итоге возообновляем блокировку файлов

def updPasswordEntryColor(*args) -> None:
    '''
    Изменяет цвет вводимого пароля в зависимости от условий
    '''
    password = passwordVar.get()

    lenght = len(password)  # Получаем длинну пароля

    if lenght <= 3:
        passwordEntry.configure(fg='green')  # Не очень надежный
    elif lenght <= 7:
        passwordEntry.configure(fg='orange')  # Хороший
    else:
        passwordEntry.configure(fg='lime')  # Отличный

root = Tk()
root.geometry('300x200')
root.title(' ')
filenameVar = StringVar(root)
passwordVar = StringVar(root)

lockedLabel = Label(root, text='locked~')
lockedLabel.pack()

Button(root, text='lock', command=lock).place(x=5, y=120)
Button(root, text='unlock', command=unlock).place(x=220, y=120)

Label(root, text='name').place(x=5, y=60)
Label(root, text='passwrd').place(x=5, y=90)

filenameEntry = Entry(root, textvariable=filenameVar)
filenameEntry.place(x=60, y=60)
filenameVar.trace_add('write', updFilenameEntryColor)  # При записи каждой новой буквы вызываетя обновление цвета для имени файла

passwordEntry = Entry(root, textvariable=passwordVar, fg='red')
passwordEntry.place(x=60, y=90)
passwordVar.trace_add('write', updPasswordEntryColor)  # аналогично

OutputLabel = Label(root, text='')
OutputLabel.place(x=5, y=160)


b = Label(root, text='?', relief='flat')
b.place(x=281, y=174)
b.bind("<Button-1>", showHelp)  # При нажатии на вопрос
b.bind("<Enter>", lambda e: lockedLabel.configure(text='click to show help'))  # При наведении на вопрос
b.bind("<Leave>", lambda e: lockedLabel.configure(text='locked~'))  # При уведении курсора с вопроса

# тестирование
# general_test()

root.mainloop()