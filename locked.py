import math
from cryptography.fernet import Fernet
from tkinter import * # type: ignore
from tkinter.messagebox import askyesno, showwarning
from time import time
from typing import Literal
from colorama import init, Fore
import os, sys
import getpass
import json
import hashlib
import keyring
import ctypes
from base64 import b64decode, b64encode
import webbrowser
from argon2.low_level import hash_secret_raw, Type
import base64
from typing import TypedDict, overload


# Настройки
SKIP_FILES = ['.DS_Store', 'auth', 'auth/keychain.txt', 'auth/security']  # Файлы, которые нельзя зашифровать и расшифровать
TEST_PASSWORD = 'pass'  # пароль для двойного нажатия control
CONSOLE_PASSWORD = ['Meta_L', 'Meta_L', 'x']  # пароль консоли?
DEVELOPER_MODE = True  # Включает некоторые функции, не нужные обычному пользователю
CONSOLE_SHORTCUTS = {'terminal': 'terminalModeAsk()'}  # Если ввести ключ в консоль, то там автоматически появится значение словаря
DELETE_SAVED_PASSWORD_AFTER_UNLOCK = True  # Удалять пароль к файлу из связки ключей после разблокировки этого файла
ADMIN_TERMINAL_DESIGN = 'kali'  # Дизайн терминала: kali, normal
TERMINAL_EXITS = ['exit', 'close', 'эхит', 'выход', 'выйти', 'закрыть']

# Уже не настройки (не изменять)
FILE = os.path.basename(sys.argv[0])
refuseBlocking = False
refuseBlockingViaPassword = False
refuseBlockingReason = None
last_incorrect_password_key = None
last_time_control_keypress = 0

DEFAULTS_MODES = Literal['ky', 'files']
ENCRYPTED_FILE_EXT = "encr"

backup = None

backup_help_showed = False

times_name_clicked = 0
console_password_inputed = []
console_command_inputed = ''

confirmed_developer_mode = None

keychain_password_inputed = ''
keychain_password = None
keychain_autofill = [] # при включеной дополнительной защите используется для показа файлов к которым соханён пароль

skey_ky_auth_requested = False

BANNED_CMD = ['banned', 'keychain_password', 'FILE', 'keyring', 'access', 'eval', 'exec', FILE, 'os.', ' os ', ' os', 'os ', 'system', 'import']


def general_test():
    '''
    Тестирует основные компоненты программы
    '''
    global backup
    # данные для тестирования:
    text_file = 'file.py'
    non_text_file = 'p.jpeg'
    password = 'qwerty1234'

    if text_file == FILE or non_text_file == FILE:
        print('нельзя шифровать сам locked')
        exit()

    if isLocked(text_file):
        print(f'сначала разблокируй {text_file}')
        exit()
    if isLocked(non_text_file):
        print(f'сначала разблокируй {non_text_file}')
        exit()

    passwordVar.set(password)
    fileVar.set(text_file)

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
    fileVar.set(non_text_file)

    lock()

    if not isLocked(non_text_file):
        print(f'файл {non_text_file} не зашифровался')
        exit()
        
    unlock()

    if isLocked(non_text_file):
        print(f'файл {non_text_file} не расшифровался')
        exit()

    passwordVar.set('')
    fileVar.set('')
    printuwu('test completed successfully', 'lime')
    backup = None
    print('TEST SUCCESS')

def redirect(to):
    """Use to temporarily redirect the functionality of old func to new\\
        For example:
        ```
        def isLocked(file:str) -> bool:
            return redirect(file.endswith('.encr'))

            ...
        ```
    """
    return to


def strToB64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8")

def B64ToStr(b64: str) -> str:
    return base64.urlsafe_b64decode(b64).decode("utf-8")


def bytesToB64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")

def B64ToBytes(b64: str) -> bytes:
    return base64.urlsafe_b64decode(b64)

class ConfigDefaultsItems(TypedDict):
    timecost: int
    memorycost: int

class ConfigDefaults(TypedDict):
    files: ConfigDefaultsItems
    ky: ConfigDefaultsItems


def defaultsGet(forr:Literal['files', 'ky']) -> tuple[int, int]:
    'returns default for `forr` like tuple `(timecost, memorycost)`'
    with open('auth/defaults') as f:
        d = f.read()
    info:ConfigDefaultsItems = json.loads(B64ToStr(d))[forr]

    return info['timecost'], info['memorycost']

def defaultsSet(new:ConfigDefaults) -> None:
    with open('auth/defaults', 'w') as f:
        f.write(strToB64(json.dumps(new)))


def derive_argon2_key(
    password: str,
    salt: bytes,
    timecost: int,
    memorycostKB: int,
) -> bytes:
    """
    Генерирует 32-байтный ключ с помощью Argon2id
    """
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=timecost,
        memory_cost=memorycostKB,
        parallelism=2,
        hash_len=32,
        type=Type.ID  # Argon2id
    )



def decryptarg(data: str, password: str, salt: bytes, timecost: int, memorycostMB: int) -> bytes | None:
    """
    Расшифровывает данные с помощью пароля и соли
    """

    # ключ из пароля + соль
    derived_key = derive_argon2_key(
        password=password,
        salt=salt,
        timecost=timecost,
        memorycostKB=memorycostMB * 1024,
    )

    # делаем из него ключ для Fernet (base64, 32 байта)
    fernet_key = base64.urlsafe_b64encode(derived_key)
    cipher = Fernet(fernet_key)

    # расшифровываем
    try: decrypted: bytes = cipher.decrypt(data.encode('utf-8'))
    except:  return None  # если пароль неверный
    return decrypted

# defaultsSet({'files': {'memorycost': 512, 'timecost': 4}, 'ky': {'memorycost': 512, 'timecost':6}})

@overload
def encryptarg(
    data: str | bytes,
    password: str,
    salt: bytes,
    *,
    timecost: int,
    memorycostmb: int
) -> bytes | None: ...
@overload
def encryptarg(
    data: str | bytes,
    password: str,
    salt: bytes,
    *,
    defaultsFor: DEFAULTS_MODES
) -> bytes | None: ...

def encryptarg(data: str | bytes, password: str, salt: bytes, timecost: int | None = None, memorycostmb: int | None = None, defaultsFor: DEFAULTS_MODES|None = None) -> bytes | None:
    """
    Шифрует данные с помощью пароля и соли\\
    При указании `timecost` и `memorycostmb` используются эти значиения\\
    При указании `useDefaultsFor` используются значения по умолчанию для переданного типа данных для шифрования
    """

    if defaultsFor:
        timecost, memorycostmb = defaultsGet(defaultsFor)
    
    if timecost is None or memorycostmb is None:
        raise Exception('overloads not satisfyed')
    
    try:
        # Приводим текст к байтам
        plaindata = data.encode('utf-8') if isinstance(data, str) else data

        # Генерируем ключ из пароля + соль
        derived_key = derive_argon2_key(password, salt, timecost, memorycostmb*1024)

        # Создаём ключ для Fernet: 32 байта → base64url
        fernetKey = base64.urlsafe_b64encode(derived_key)
        cipher = Fernet(fernetKey)

        # Шифруем
        encrypted_data = cipher.encrypt(plaindata)

        return encrypted_data

    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

def make_key(password:str|None=None, mode:Literal['old', 'new']='new') -> str:
    '''
    Создаёт ключ для Fernet
    '''


    if password:
        key = password
    else:
        key = str(passwordVar.get())
    
    if use_old_encryption:
        mode = 'old'

    if mode == 'old':
        key = (key * 44)[:43] + '='
    elif mode == 'new':
        key = hashlib.sha256(key.encode()).hexdigest()[:43] + '='
    else:
        showwarning('', 'unknown mode in make_key')
        raise('unknown mode in make_key')
        return

    return key

class ConfigEncFile(TypedDict):
    encrypted: str
    salt: bytes
    timecost:int
    memorycost:int
        
def readEncFile(file:str, *, rm:bool=True) -> ConfigEncFile:
    """
    reads file and returns ```{"encrypted": ..., "salt": ..., "timecost": ..., "memorycost": ...}```\\
    `rm` to delete file after reading it
    """
    
    with sopen(file, 'r') as f:
        d = f.read()
    if rm:
        os.remove(file)
    c = parseEncConfig(d)
    return c

@overload
def makeEncFile(
    file: str,
    encrypted: str | bytes,
    salt: bytes,
    *,
    rm:bool=True,
    timecost_used: int,
    memorycost_used: int
) -> None: ...
@overload
def makeEncFile(
    file: str,
    encrypted: str | bytes,
    salt: bytes,
    *,
    rm:bool=True,
    defaultsFor: DEFAULTS_MODES
) -> None: ...

def makeEncFile(
    file: str,
    encrypted: str | bytes,
    salt: bytes,
    *,
    rm:bool=True,
    timecost_used: int | None = None,
    memorycost_used: int | None = None,
    defaultsFor: DEFAULTS_MODES | None = None,
) -> None:
    """
    creates file `"{file}.{ENCRYPTED_FILE_EXT (.encr)}"` and puts data in it
    """
    if defaultsFor:
        timecost_used, memorycost_used = defaultsGet(defaultsFor)
    if timecost_used is None or memorycost_used is None: 
        raise
    
    cfg = makeEncConfig(encrypted, salt, timecost_used=timecost_used, memorycost_used=memorycost_used)

    with open(f'{file}.{ENCRYPTED_FILE_EXT}', 'x') as f:
        f.write(cfg)
    
    if rm:
        os.remove(file)

def parseEncConfig(cfg:str) -> ConfigEncFile:
    cgf = cfg.split('.')
    b64info = cgf[1]
    info:ConfigEncFile = json.loads(B64ToStr(b64info))
    info['encrypted'] = cgf[0]
    info['salt'] = B64ToBytes(info['salt']) # type: ignore
    return info

def makeEncConfig(
    encrypted: str | bytes,
    salt_used: bytes,
    *,
    timecost_used: int | None = None,
    memorycost_used: int | None = None,
    defaultsFor: DEFAULTS_MODES | None = None
) -> str:
    """
    Returns string ready for writing to encr file. Like 
```
b64info = strToB64({"salt": bytesToB64(...), "timecost": ..., "memorycost": ...})
f'{encrypted}\\n{b64info}'
```
    """
    if defaultsFor:
        timecost_used, memorycost_used = defaultsGet(defaultsFor)
    if timecost_used is None or memorycost_used is None: 
        raise
    
    encrypted = encrypted.decode() if isinstance(encrypted, bytes) else encrypted

    info = json.dumps(
        {
            "salt": bytesToB64(salt_used),
            "timecost": timecost_used,
            "memorycost": memorycost_used 
        }
    )
    b64info = strToB64(info)
    return f'{encrypted}.{b64info}'


    


def encrypt_data(text:str|bytes, key=None) -> str|None: 
    raise
    '''
    Зашифровывает переданный текст
    '''

    s = redirect(encryptarg(text, passwordVar.get(), b'123123123123123123123123123', 4, 512))
    if s: return s.decode('utf-8')
    return

    text = text.encode() if isinstance(text, str) else text  # Если текст в строке, то переводим его в байты
    
    if key:
        cipher_key = key
    else:
        cipher_key = make_key()  # Генерируем ключ для шифровки

    try:
        cipher = Fernet(cipher_key)
    except:
        if cipher_key.startswith('/sKey//'):
            printuwu('Custom sKey failed:', extra=True, color='magenta')
        printuwu('unable to create key with this passwrd.\nPasswrd contains prohibited char(s)')  # В норме не выводится, а перекрывается другим
        return

    encrypted_text = cipher.encrypt(text)  # Шифруем

    return encrypted_text.decode('utf-8')

def decrypt_data(text, key=None) -> bytes|None:
    raise
    '''
    return:\\
    str - зашифрованый текст\\
    bytes - зашифрованые байты\\
    None - ошибка ключа/пароля
    '''

    s =  redirect(decryptarg(text, passwordVar.get(), b'123123123123123123123123123', 4, 512))
    if s: return s
    return

    if key:
        cipher_key = key
    else:
        cipher_key = make_key()  # Создаём ключ
    try:  cipher = Fernet(cipher_key)
    except:
        return
    
    try:
        decrypted_text = cipher.decrypt(text)  # Если нужны байты, то не переводим из них в str
    except:
        return
    
    if isinstance(decrypted_text, bytes):
        return decrypted_text
    elif isinstance(decrypted_text, str):
        return decrypted_text.encode('utf-8')
    else:
        return decrypted_text
    
    
    try:  # Пытаемся перевести в строку
        decrypted_text = decrypted_text.decode('utf-8')
    except:
        ...
    
    return decrypted_text


def isLocked(file:str) -> bool:
    if isFileExist(file, strict=True):
        return redirect(file.endswith(f'.{ENCRYPTED_FILE_EXT}'))
    if isFileExist(file + f'.{ENCRYPTED_FILE_EXT}', strict=True):
        return True


    if getFileType(file) == 'bytes':
        with open(file, 'rb') as f:
            data = f.read()
            try:  # Если получается преобразовать в utf8, то значит зашифровано
                data = data.decode('utf-8')
                return True
            except:  # Если нет, то расшифровано
                return False
            
    else:
        with open(file, 'r') as f:
            data = f.read()
            if data[:4] == 'gAAA':  # Если начинается с этих символов, то он зашифрован
                return True
            return False
        
def isUnlocked(file:str) -> bool:
    '''
    Разблокирован ли файл
    '''
    return not isLocked(file)

def getFileFormat(file:str) -> str:
    '''
    Получить расширение файла (без точки)
    Пример: jpeg\\
    Для папки вернёт folder
    '''
    if '.' in file:
        dotindex = file.index('.')
        return file[dotindex+1:]
    else:
        return 'folder'
    
def getFileName(file) -> str|None:
    if '.' in file:
        dotindex = file.index('.')
        return file[:dotindex]


def lockFolder(folder):
    '''
    Блокирует все файлы в папке
    '''
    for file in os.listdir(f'{os.getcwd()}/{folder}'):
        lock(f'{folder}/{file}', folderMode=True)

def unlockFolder(folder):
    '''
    Разблокирует все файлы в папке
    '''
    for file in os.listdir(f'{os.getcwd()}/{folder}'):
        unlock(f'{folder}/{file}', folderMode=True)

def isFileAbleToCryptography(file:str, folderMode:bool, terminalMode:bool, mode:Literal['lock', 'unlock'], forced:bool=False):
    '''
    Можно ли разблокировать/блокировать файл прямо сейчас

    forced: bool - проверить только на то, не являетяся ли шифруемый файл локедом. (полезно при выполнении принудительных действий)
    '''

    if file == os.path.basename(sys.argv[0]): # Если каким-то чудом проскочило имя самого locked, то аварийно выходим 
        if terminalMode:
            return 'locked~ cant block itself'
        printuwu('locked~ cant block itself', '#9933CC')
        return False
    
    if forced:
        return True

    if refuseBlocking or refuseBlockingViaPassword:  # Если остановлена блокировка файлов (например когда попытка блокировки этого файла)
        if refuseBlockingReason:
            if terminalMode:
                return f'cryptography is currently unavailable.\n{refuseBlockingReason}'
            printuwu(f'cryptography is currently unavailable.\n{refuseBlockingReason}', color='#9933CC')
        else:
            if terminalMode:
                return 'cryptography is currently unavailable'
            printuwu('cryptography is currently unavailable', color='#9933CC')
        return False
    
    if not file:
        if terminalMode:
            return 'name..?'
        printuwu('name..?')
        return False
    
    if not isFileExist(file, strict=False):
        if terminalMode:
            return 'file not found'
        printuwu('file not found')
        return False
    
    for skip_file in SKIP_FILES:
        if skip_file == file:
            if folderMode:
                return False
            
            if terminalMode:
                if mode == 'lock':
                    return 'you cant lock it'
                elif mode == 'unlock':
                    return 'you cant unlock it'
                
            if mode == 'lock':
                printuwu('you cant lock it')
            elif mode == 'unlock':
                printuwu('you cant unlock it')
            return False

    if not passwordVar.get():  # Если не введён пароль
        if not isSkeyEnabled():
            if terminalMode:
                return 'passwrd..?'
            printuwu('passwrd..?')
            return False

    if not getFileFormat(file) == 'folder':
        if mode == 'lock':
            if isLocked(file):  # Если файл уже заблокирован
                if terminalMode:
                        return 'locked already'
                printuwu(f'locked already')
                return False
        elif mode == 'unlock':
            if isUnlocked(file):  # Если файл уже заблокирован
                if terminalMode:
                    return 'unlocked already'
                printuwu('unlocked already')
                return False
        else:
            printuwu('unknown mode. check isFileAbleToCryptography')
            return False
        
    if isFileExist(getEncrFilename(file)) and mode == 'lock':
        printuwu('Encrypted version of the file already exists')
        return
    elif isFileExist(getOriginalFilename(file)) and mode == 'unlock':
        printuwu('Decrypted version of the file already exists')
        return
    
    

    return True

class sopen:
    """
    Позволяет открыть любой из файлов `file, file + ".encr"`\\
    Использовать если было `isFileExists` с `strict = False` и поэтому неизвестно, существует файл с обычным расширением или с .encr
    """
    def __init__(self, filename:str, mode:str):
        self.filename = filename
        self.mode = mode
        self.file = None

    def __enter__(self):
        if isFileExist(self.filename, strict=True):
            self.file = open(self.filename, self.mode)
        elif isFileExist(self.filename + f".{ENCRYPTED_FILE_EXT}", strict=True):
            self.file = open(self.filename + f".{ENCRYPTED_FILE_EXT}", self.mode)
            self.filename += f".{ENCRYPTED_FILE_EXT}"
        else:
            raise FileNotFoundError(f'None of file or file.{ENCRYPTED_FILE_EXT} found')

        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
        return False

def getFileType(file:str) -> Literal['text', 'bytes']:
    '''
    Возвращает тип файла (текстовый или нет)
    '''
    try:
        with open(file, 'r') as f:
            stream = f.read()
    except:
        return 'bytes'
    else:
        return 'text'
    
def lock(file=None, folderMode=False, terminalMode=False, forced=False):
    '''
    Блокирует файл
    '''
    if file is None:
        file = fileVar.get()  # Получаем имя файла

    password = passwordVar.get()
    
    able = isFileAbleToCryptography(file, folderMode, terminalMode, 'lock', forced=forced)
    if able != True:
        return able
    
    if isSkeyEnabled():
        passwordVar.set(_skeyCreate())
    
    if keychain_password: # если аутентифицировались в keychain, то будет сохранён пароль
        if isExtraSecurityEnabled():
            printuwu('authing KeyChain...', 'pink', extra=True)
            root.update()
        _keychainAddFileAndPassword(file, passwordVar.get())
    if isExtraSecurityEnabled():
        printuwu('', extra='clearextra')

    autofillLabel.configure(text='')

    # try:
    if 1:
        if getFileFormat(file) == 'folder':
            lockFolder(file)
            return
        
        if folderMode:
            printuwu(f'{getFileName(file)}...')
            root.update()

        salt = os.urandom(32)

        global backup
        mode = 'rb' if getFileType(file) == 'bytes' else 'r'
        with sopen(file, mode) as f:
            data:str|bytes = f.read()  # Получаем данные из файла

        encrypted_data = encryptarg(data, password, salt, defaultsFor='files') # Зашифровываем их

        backup = data

        if file == os.path.basename(sys.argv[0]): # Если каким-то чудом проскочило имя самого locked, то аварийно выходим 
            print('Tried to lock locked')
            exit()
            return
        
        if not encrypted_data:
            printuwu('encryption failed (249)', 'red')
            return
        

        makeEncFile(file, encrypted_data, salt, defaultsFor='files')
        printuwu('successful', '#00ff7f')

        # with open(file, 'w') as f:
        #     if encrypted_data is not None:
        #         f.write(encrypted_data)  # Перезаписываем файл зашифроваными данными
        #         printuwu('successful', '#00ff7f')
        #     else:
        #         printuwu('encryption failed (249)', 'red')

    # except:
    #     if backup:
    #         show_backup_help()
    
def unlock(file=None, folderMode=False, terminalMode=False, forced=False):
    '''
    Разблокирует файл, перенаправляя в нужную функцию
    '''
    if file is None:
        file = fileVar.get()  # Получаем имя файла

    able = isFileAbleToCryptography(file, folderMode, terminalMode, 'unlock', forced=forced)
    if able != True:
        return able
    
    if keychain_password:
        if DELETE_SAVED_PASSWORD_AFTER_UNLOCK:
            if isExtraSecurityEnabled():
                printuwu('authing KeyChain...', 'pink', extra=True)
                root.update()
            
    if isExtraSecurityEnabled():
        printuwu('', extra='clearextra')

    autofillLabel.configure(text='')

    # try:
    if 1:
        if getFileFormat(file) == 'folder':
            unlockFolder(file)
            return
        
        if folderMode:
            printuwu(f'{getFileName(file)}...')
            root.update()

        global backup
        data:ConfigEncFile = readEncFile(file, rm=False)


        decrypted_data = decryptarg(data['encrypted'], passwordVar.get(), data['salt'], data['timecost'], data['memorycost'])
        if decrypted_data is None:  # Если вернула None, значит ошибка пароля
            printuwu('incorrect passwrd')
            return
        
        backup = data

        with open(getOriginalFilename(file), 'wb') as f:  # Открываем файл для перезаписи в бинарном режиме
            f.write(decrypted_data.encode() if isinstance(decrypted_data, str) else decrypted_data)  # Перезаписываем зашифрованными данными
        printuwu('successful', '#00ff00')
        os.remove(getEncrFilename(file))
        _keychainRemoveFileAndPassword(file, keychain_password) if keychain_password else ...

    # except:
    #     if backup:
    #         show_backup_help()

def getEncrFilename(file: str) -> str:
    """
    Get filename with .encr
    """
    s = file if file.endswith('.encr') else file + f'.{ENCRYPTED_FILE_EXT}'
    return s

def getOriginalFilename(file: str) -> str:
    """
    Get filename without .encr 
    """
    s = file[:file.rfind(f'.')] if file.endswith('.encr') else file
    return s

def printuwu(text: str, color:str|None=None, extra:Literal[True, 'clear', 'clearextra']|bool=False) -> None:
    '''
    Выводит текст в специальное место программы слева снизу
    extra: True чтобы вывести в дополнительное место; clear чтобы очистить все поля вывода \\
    // Мне кажется это вообще тут самая главная функция 💀
    '''
    if extra == 'clear':
        OutputLabel.configure(text='')
        ExtraOutputLabel.configure(text='')
        return
    elif extra == 'clearextra':
        ExtraOutputLabel.configure(text='')
        return
    
    if not extra:
        OutputLabel.configure(text=text)
        if color:
            OutputLabel.configure(fg=color)
        else:
            OutputLabel.configure(fg='systemTextColor')  # Цвет темы в мак ос
    elif extra:
        ExtraOutputLabel.configure(text=text)
        if color:
            ExtraOutputLabel.configure(fg=color)
        else:
            ExtraOutputLabel.configure(fg='systemTextColor')  # Цвет темы в мак ос

def showHelp() -> None:
    '''
    Показывает справку в терминале
    '''
    # lockedLabel.configure(text='check terminal')
    print('''\nlocked~
==БЛОКИРОВКА ФАЙЛОВ==
Введи имя файла/относительный путь к нему и пароль, нажми lock / unlock
          

==ЦВЕТА==
          
name:
    лайм - всё хорошо
    красный - неверное имя файла
    фиолетовый - нельзя блокировать сам locked~
          

==БЭКАПЫ==
Если при блокировке/разблокировке файла произошла какая-либо ошибка и он очистился, то его всё ещё можно восстановить (не закрывай locked~ в таком случае). Для этого введи имя этого файла в name если оно не введено, пароль вводить не надо. После этого следует нажать на вопросительный знак справа снизу ПКМ, после чего откроется меню бэкапа, и нужно будет выбрать действие нажатием клавиши:

[0] Отмена, выход из меню бэкапа (однако бэкап сохранится в оперативной памяти)
[1] Восстановить файл из текущего бэкапа
[2] Записать данные бэкапа в новый файл, на случай если по каким-либо причинам не удаётся восстановить сам файл
[Command] + [D] Безвозвратно далить бэкап, после этого восстановление файла станет невозможным.

          
==КОНСОЛЬ==
          
Чтобы открыть мини-консоль прямо в окне locked~ необходимо три раза нажать на текст "name". После этого нужно выбрать действие:
[0] Отмена, закрыть консоль
[1] Ввести пароль и открыть консоль
          
При нажатии [1] необходимо будет ввести пароль от консоли, который был задан в "CONSOLE_PASSWORD"
После этого откроется консоль. Для того, чтобы убрать фокусоровку с полей ввода нажми [option]
Для того, чтобы выполнить exec введёной команды нажми правый Shift
Чтобы выполнить eval команды нажми [Enter]
Консоль работает примерно как консоль питона
Для выхода нажми [esc]

Если вышла надпись access denied, значит либо не включен режим разработчика, либо было нажато "нет" в всплывающем окне с подтверждением намерения.

          
==ТЕРМИНАЛ==

В locked~ есть режим работы в терминале. Для его включения нужно нажать на текст "term" слева сверху.
После этого будет предложен выбор:
[0] Отменить и остаться в Tkinter
[1] Запустить режим терминала

Если включен режим разработчика, то будет предложено выбрать терминал: админский с полным доступом к питону или пользовательский, в котором есть только заготовленные команды. 

В режиме админа можно вводить любые команды, поддерживаемые питоном (некоторые отключены в целях безопасности)
Для выполнения eval команды достаточно просто ввести её и нажать [Enter]
Для выполнения exec команды нужно добавить перед ней "do". Пример: do a = 5. 
          
В режиме пользователя можно вводить только заранее заготовленные команды, например для блокировки и разблокировки файла
Для получения списка команд и метода их использования введи "help".
          
Для выхода из режима терминала введи "exit"
          
==СВЯЗКА КЛЮЧЕЙ==

keychain! Система, которая может запомнить и безопасно, зашифровано хранить введёные пароли к файлам для их дальнейшего просмотра или быстрого автозаполнения. Для всего этого необходимо сначала создать связку ключей.

Чтобы сделать это достаточно нажать на open keychain слева сверху, после чего создать главный пароль, с помощью которого будет шифроваться вся связка ключей. Если его забыть, то восстановить сохранёные пароли будет невозможно. Данный пароль никогда не сохраняется на диске, поэтому при закрытии программы его точно нигде не останется. Однако он может быть временно сохранён в переменной для доступа к автозаполнению и сохранению новых паролей. 

Для этого нужно нажать на auth keychain слева сверху. После этого нужно будет ввести свой главный пароль от связки ключей и нажать [Enter]. При вводе неверного пароля он подсветится красным. При вводе правильного пароля надпись "auth keychain" станет зелёной, что означает успешный вход в связку ключей и доступа к автозаполнению старых паролей, сохранению новых и беспарольному доступу к просмотру сохранёных паролей, ведь главный пароль сохранён в переменной
          
Чтобы выйти из связки ключей достаточно нажать на зелёную надпись auth keychain. После выхода главный пароль удаляется из переменной, и автозаполнение с сохранением паролей становится недоступным. Выход не повлияет на сохранёные пароли и данные.
          
(При нажатии на "open keychain" открываются пароли, но авторизация не сохраняется, Чтобы авторизоваться нужно нажать на auth keychain)

''')

def updFileEntryColor(*args) -> None:
    '''
    Изменяет цвет вводимого имени файла в зависимости от условий
    '''
    global refuseBlocking
    file = fileVar.get()

    if file == FILE:  # Если ввели этот файл (сам locked)
        fileEntry.configure(fg='#9933CC')
        # printuwu('locked cant lock itself', color='#9933CC')
        refuseBlocking = True  # Останавливаем блокировку файлов, чтобы не заблокировать себя
        disablepasswordEntry()
        return
    else:
        if not isSkeyEnabled():
            enablepasswordEntry()

    autofill('check')

    if isFileExist(file) or isFileExist(f'{file}.{ENCRYPTED_FILE_EXT}'):
        fileEntry.configure(fg='lime')
    else:
        fileEntry.configure(fg='red')

    refuseBlocking = False  # В итоге возообновляем блокировку файлов

def updPasswordEntryColor(*args) -> None:
    '''
    Изменяет цвет вводимого пароля в зависимости от условий, проверяет его на действительность и возможность использования как пароль
    '''
    redirect(passwordEntry.configure(fg='lime'))
    return


    global last_incorrect_password_key, refuseBlockingViaPassword, refuseBlockingReason
    password = passwordVar.get()
    if password.startswith('/sKey//'):
        passwordEntry['fg'] = 'magenta'
        return
    
    lenght = len(password)  # Получаем длинну пароля

    try:  # Пробуем создать ключ с паролем на момент ввода
        Fernet(make_key('a'+password))
    except:  # Если не получилось, то
        password_with_space = 'abc' + password # Если поле для ввода пустое, то будет ошибка. поэтому добаляем a в начало, чтобы ошибки не было
        try:  # пробуем создать ключ с последним символом пароля (только что введённым)
            Fernet(make_key(password_with_space[-1]))
        except:  # Если не получилось, то
            last_incorrect_password_key = password_with_space[-1]  # Запоминаем этот символ
        if last_incorrect_password_key == ' ':
            printuwu(f'passwrd cant contain space', 'red')  # Выводим его
        else:
            if last_incorrect_password_key is not None:
                printuwu(f'incorrect symbol in the passwrd: {last_incorrect_password_key}', 'red')  # Выводим его
            else:
                printuwu('', extra='clear')
        passwordEntry.configure(fg='red')  # Делаем пароль красным
        refuseBlockingViaPassword = True

        refuseBlockingReason = f'incorrect symbol in the passwrd: {last_incorrect_password_key}'
        return
    else:
        if last_incorrect_password_key:
            printuwu('')  # Если всё хорошо, то убираем надпись
            last_incorrect_password_key = None
    
    if lenght > 40 and use_old_encryption:  # Если длинна пароля больше 40 символов при старом шифровании
        passwordEntry.configure(fg='red')
        printuwu('passwrd cant be longer than 40 symbols')
        refuseBlockingViaPassword = True
        refuseBlockingReason = 'the passwrd is too long'
        return

    passwordEntry.configure(fg='lime')  # Отличный
    refuseBlockingViaPassword = False
    refuseBlockingReason = None

def isFileExist(file:str, strict:bool = True) -> bool:
    '''
    Возвращает True если файл/папка/файл по определённому пути существует, иначе False\\
    strict=True позволяет найти существование именно этого файла\\
    strict=False позволяет найти в том числе и file + .encr то есть `any(exists(file), exists(file.encr))`

    '''
    def r(file:str):
        if file == '' or file == '/':
            return False
        if getFileFormat(file) == 'folder':
            if file in os.listdir(os.getcwd()):
                return True
            return False
        try:
            open(file, 'r')
        except:  # Если не найден файл
            return False
        else:
            return True
    if not strict:
        return any(r(f) for f in [file, file + f'.{ENCRYPTED_FILE_EXT}'])
    if strict:
        return r(file)

def autofill(action:Literal['replace', 'check']) -> None:
    '''
    При action=replace автоматически дополняет введённое имя файла\\
    При action=check проверяет, если ли доступные автозамены 
    '''
    global autofillLabel
    currentFile = fileVar.get().replace('.', '')

    if currentFile == '':
        autofillLabel.configure(text='')
        return
    
    dir_mode = False
    if '/' in currentFile:
        dir_mode = True
        dirr = f'{os.getcwd()}/{currentFile[:currentFile.index('/')]}'
    else:
        dirr = os.getcwd()
    try:
        if currentFile[-1] == '/':
            autofillLabel.configure(text='')
            return
    except:
        pass

    autofill_found = False


    files = os.listdir(dirr)
    file = ''

    # for file in files.copy():
    #     files.append(f'{file}.{ENCRYPTED_FILE_EXT}')

    for file in files:
        if file == FILE:
            continue
        file_found = file.startswith(currentFile)
        if not file_found:
            try:
                file_found = file.startswith(currentFile[currentFile.index('/')+1:])
            except : ...
        if file_found:
            autofill_found = True
            if action == 'replace':
                if dir_mode:
                    fileVar.set(f'{currentFile[:currentFile.index('/')]}/{file}')
                else:
                    fileVar.set(f'{getOriginalFilename(file)}')
                if getFileFormat(file) == 'folder':
                    autofillLabel.configure(text='')
            elif action == 'check':
                if not currentFile == '':
                    if getFileFormat(file) == 'folder':
                        autofillLabel.configure(text=f'{file}', fg='#ffc0cb')
                    else:
                        autofillLabel.configure(text=f'{getFileName(file)}\n.{getFileFormat(getOriginalFilename(file))}', fg='#ffc0cb')
                else:
                    autofillLabel.configure(text='')
            else:
                print(f'incorrect action: {action}')
            break
        
    if autofill_found:
        if keychain_password: # if logged in keychain
            if isExtraSecurityEnabled():
                keychainFiles = keychain_autofill
            else:
                if keychainCheckKyPassword(keychain_password):
                    keychainFiles = _keychainDecrypt(keychain_password)
                else:
                    return
            if dir_mode:
                filedir = f'{currentFile[:currentFile.index('/')]}/{file}'
            else:
                filedir = file
            if not isinstance(keychainFiles, dict):
                printuwu('autofill Failed', 'red')
                return
            if isExtraSecurityEnabled():
                if not filedir in keychain_autofill:
                    return 
            else:
                if not filedir in keychainFiles.keys():
                    return
                
            if not currentFile == '':
                if getFileFormat(file) == 'folder':
                    autofillLabel.configure(text=f'{file}', fg='magenta')
                else:
                    autofillLabel.configure(text=f'{getFileName(file)}\n.{getFileFormat(file)}', fg='magenta')

            if action == 'replace':
                if isExtraSecurityEnabled():
                    printuwu('authing through KeyChain...', 'pink', extra=True)
                    root.update()
                    keychainFiles = _keychainDecrypt(keychain_password)
                    printuwu('', extra='clearextra')

                    if not type(keychainFiles) == dict:
                        return
                if keychainFiles[filedir].startswith('/sKey//'):
                    _skeyEnable()
                passwordVar.set(keychainFiles[filedir])
                removeFocus()
                    
    
    if not autofill_found or not currentFile:
        autofillLabel.configure(text='')

def insertTestPassword():
    """
    Вводит тестовый пароль в строку ввода пароля (быстро нажми control 2 раза)
    """
    global last_time_control_keypress
    
    current_time = time()
    if current_time - last_time_control_keypress >= 0.3:
        last_time_control_keypress = time()
    else:
        if isSkeyEnabled():
            printuwu('Disable sKey to Use Quick Password', 'pink')
            return
        passwordVar.set(TEST_PASSWORD)
        last_time_control_keypress = 0

def preventClosing() -> None:  # устаревшая функция
    """
    Функция, перехватывающая попытку закрыть окно (но не cmd+q) при поломке файла, чтобы случайно не потерять бэкап сломаного файла
    """
    print('\n\n\n\nIf you will exit now you will lose your backup so you wont be able to restore it.\nTo stay in locked and continue recovering file press Enter in the terminal.\nTo close window and LOSE YOUR FILE enter "lose" and press Enter.')
    action = input('so: ')
    if action == 'lose':
        root.destroy()
        root.protocol("WM_DELETE_WINDOW", lambda x=None: exit())
        exit()

def removeFocus():
    """
    Убирает фокусировку ввода со всех Entry
    """
    root.focus()

def show_backup_help():
    """
    Запустить предупреждение о поломке файла и необходимости его восстановить, открыть меню бэкапа, добавить подтверждение для выхода
    """
    global backup_help_showed
    
    lockedLabel.configure(text='Кажется, произошла ошибка и файл сломался.\nпомощь выведена в терминал\nДля закрытия наведи мышку на вопросик', 
    bg='gray20')

    # helpLabel.unbind("<Enter>")
    # helpLabel.unbind("<Leave>")
    # helpLabel.unbind("<Button-1>")
    backup_help_showed = True
    print(f'{Fore.LIGHTMAGENTA_EX}Если файл сейчас сломан (например, он пустой), то его можно восстановить из бэкапа (при его наличии).\nЕсли по каким-то причинам меню бэкапа снизу не открылось, введи имя файла в поле name (если оно не введено) и нажми ПКМ на вопросительный знак справа снизу. После этого откроется меню бэкапа, и нужно будет выбрать действие нажатием клавиши:\n{Fore.LIGHTBLUE_EX}[1]{Fore.LIGHTCYAN_EX} Восстановить файл из текущего бэкапа\n{Fore.LIGHTBLUE_EX}[2]{Fore.LIGHTCYAN_EX} Записать данные бэкапа в новый файл, на случай если по каким-либо причинам не удаётся восстановить сам файл{Fore.RESET}')
    backupFile()

def remove_backup_help():
    """
    Убрать предупреждение о поломке файла
    """
    global backup_help_showed
    lockedLabel.configure(text='locked~', bg='systemWindowBackgroundColor')

    helpLabel.bind("<Button-1>", lambda e: showHelp())
    helpLabel.bind("<Enter>", lambda e: lockedLabel.configure(text='click to show help\nright click to backup'))
    helpLabel.bind("<Leave>", lambda e: lockedLabel.configure(text='locked~'))
    backup_help_showed = False
    root.protocol("WM_DELETE_WINDOW", exit)


def _backup_run(e=None):
    """
    Пробует восстановить файл из бэкапа
    """
    file = fileVar.get()
    if type(backup) == str:
        with open(file, 'w') as f:
            f.write(backup)
    
    elif type(backup) == bytes:
        with open(file, 'wb') as f:
            f.write(backup)
    elif backup is None:
        printuwu('no backup??')
        return
    _backup_cancel()
    if backup_help_showed:
        remove_backup_help()
    
    printuwu(f'successfully backuped {file}\nfrom [{backup[:5]} ...]', 'lime')
    return f'successfully backuped {file}\nfrom [{backup[:5]} ...]'

def _backup_dump(e=None):
    """
    Создать файл и записать в него бэкап, на случай если по какой-либо причине не получилось восстановить файл.
    """
    try:
        with open('backup_dump_bytes', 'xb') as f:
            f.write(backup) # type: ignore
    except:
        with open('backup_dump_text', 'x') as f:
            f.write(backup) # type: ignore
    _backup_cancel()
    if backup_help_showed:
        remove_backup_help()
    if backup is None:
        printuwu('no backup??')
        return
    if isinstance(backup, (bytes, bytearray, memoryview)):
        printuwu(f'successfully dumped\n[{backup[:5]} ...]', 'lime')
        return
    printuwu(f'successfully dumped\n[{backup.replace("\n", " ")[:10]} ...]', 'lime')
    return f'successfully dumped\nfrom {backup.replace("\n", " ")[:10]} ..', 'lime'

def _backup_delete_confirm(e=None):
    """
    Удаляет текущий бэкап без подтверждения
    """
    global backup
    backup = None
    printuwu('backup successfully deleted', 'red')
    _backup_cancel()

    if backup_help_showed:
        remove_backup_help()
    return 'backup successfully deleted'

def _backup_delete_aks(e=None):
    """
    Запрашивает подтверждение, точно ли удалить бэкап
    """
    _backup_cancel()

    printuwu('[0] CANCEL and keep backup\n[1] DELETE backup', 'red')

    root.bind('0', _backup_cancel)
    root.bind('1', _backup_delete_confirm)

def _backup_cancel(e=None):
    '''
    Сбросить все бинды для бэкапа и очистить поля вывода
    '''
    root.unbind('<Meta_L><0>')        
    root.unbind('0')
    root.unbind('1')
    root.unbind('2')
    printuwu('', extra='clear')
    
def backupFile():
    """
    Выводит информацию о бэкапе
    """
    file = fileVar.get()
    removeFocus()

    if backup is None:
        printuwu('there is no backup...')
        return

    if not file:
        printuwu(f'enter file, then press\nagain to backup it')
        return
    
    try:
        open(file)
    except:
        printuwu(f'enter file, then press\nagain to backup it')
        return
    
    printuwu(f'[0] Cancel | [⌘D] Delete backup |  {file}', 'orange', True)
    printuwu(f'[1] RECOVERY {file}\n[2] Dump backup [{backup[:5]}...]', 'lime')

    root.bind('<Meta_L><d>', _backup_delete_aks)        
    root.bind('0', _backup_cancel)
    root.bind('1', _backup_run)
    root.bind('2', _backup_dump)


def _consoleClearInputedCommand(e=None):
    """
    Очистить введёную в консоль команду, но не обновлять поле для ввода
    """
    global console_command_inputed

    console_command_inputed = ''

def _consoleExecuteCommand(mode:Literal['exec', 'eval']):
    """
    Выполнить введёную команду при определённых условиях
    """
    global confirmed_developer_mode
    if not DEVELOPER_MODE:
        printuwu('access denied', 'red')
        return
    
    if confirmed_developer_mode is None:
        answer = askyesno('warning', f'Неправильное использование команд может сломать программу и/или ваши файлы, или даже больше. Продолжай на свой страх и риск. Запустить [{console_command_inputed}] и все последующие команды в этом сеансе?')
        confirmed_developer_mode = answer

    if confirmed_developer_mode == False:
        printuwu('access denied', 'red')
        _consoleClearInputedCommand()
        return
    
    if not console_command_inputed:
        return

    for ban in BANNED_CMD:
        if ban in console_command_inputed:
            printuwu(f'Access Denied: "{ban}"\nis prohibited to use in locked~ console', 'red')
            _consoleClearInputedCommand()
            return
    safe_globals = {}
    try:
        if mode == 'eval':
            result = eval(console_command_inputed, safe_globals)
        elif mode == 'exec':
            result = exec(console_command_inputed, safe_globals)
        else:
            printuwu(f'incorrect mode: {mode}', 'red')
            return
    except Exception as e:
        printuwu(f'{e}', 'red')
    else:
        printuwu(result, 'lime')
    finally:
        _consoleClearInputedCommand()

def _consoleAddCharToCommand(e):
    """
    Добавляет нажатую клавишу в консоль
    """
    global console_command_inputed

    char = e.char
    keysym = e.keysym
    if keysym == 'Escape':
        _consoleReset()
        console_command_inputed = ''
        return
    elif keysym == 'BackSpace':
        if console_command_inputed:
            console_command_inputed = console_command_inputed[:-1]
        printuwu(f'{console_command_inputed}', 'orange')
        return
    elif keysym == 'Return':
        _consoleExecuteCommand('eval')
        return
    elif keysym == 'Shift_R':
        _consoleExecuteCommand('exec')
        return
    
    console_command_inputed += char

    if console_command_inputed in CONSOLE_SHORTCUTS:
        console_command_inputed = CONSOLE_SHORTCUTS[console_command_inputed]

    printuwu(f'{console_command_inputed}', 'orange')

add_char_to_command_ID = None  # To unbind in the future
def _consoleRun(e=None):
    """
    Запустить консоль
    """
    global add_char_to_command_ID
    _consoleReset()
    printuwu('enter command | esc to exit', 'orange', True)
    
    add_char_to_command_ID = root.bind('<KeyPress>', _consoleAddCharToCommand)

def _consoleAddCharToPassword(e):
    """
    Добавить нажатую клавишу к полю ввода пароля
    """
    global console_password_inputed

    char = e.keysym
    if char == 'Escape':
        _consoleReset()
        return
    elif char == 'BackSpace':
        if console_password_inputed:
            console_password_inputed.pop()
        printuwu(f'{' '.join(console_password_inputed)}', 'orange')
        return
    
    console_password_inputed.append(char)

    printuwu(f'{' '.join(console_password_inputed)}', 'orange')

    if console_password_inputed == CONSOLE_PASSWORD:
        console_password_inputed.clear()
        _consoleRun()

add_char_to_password_ID = None  # To unbind in the future
def _consoleEnterPassword():
    """
    Запросить пароль для консоли
    """
    global add_char_to_password_ID
    _consoleReset()

    printuwu('enter console passwrd | esc to exit', 'orange', True)

    add_char_to_password_ID = root.bind('<KeyPress>', _consoleAddCharToPassword)

def _consoleReset(e=None):
    """
    Разбиндить все клавиши, используемые для консоли и очистить поле вывода
    """
    try:
        root.unbind('0')
        root.unbind('1')
    except:
        pass

    try:
        root.unbind('<KeyPress>', add_char_to_password_ID)
    except:
        pass

    try:
        root.unbind('<KeyPress>', add_char_to_command_ID)
    except:
        pass
    
    printuwu('', extra='clear')

def colsoleOpenAks():
    """
    Спросить, уверен ли пользователь что он хочет открыть консоль
    """
    global times_name_clicked
    if times_name_clicked < 2:
        times_name_clicked += 1
        return
    removeFocus()
    printuwu('U are trying to open developer console. It is dangerous!', 'orange', True)
    printuwu('[0] Cancel and quit console\n[1] Enter password and run console')
    root.bind('0', lambda e: _consoleReset())
    root.bind('1', lambda e: _consoleEnterPassword())


class CustomCommandsHandler:
    def __init__(self) -> None:
        self.COMMANDS = ['lock', 'unlock', 'backup', 'help']

    def run(self, command:str):
        try:
            command, *args = command.split()
        except:
            return ''
        if command in self.COMMANDS:
            return eval(f'self._{command}({args})')
        return 'undefined command. You can type "help"'
        
    def __crypto(self, mode:Literal['lock', 'unlock'], args):
        try: 
            file = args[0]
            password = args[1]
        except:
            if mode == 'lock':
                return 'usage: lock <file> <password>'
            else:
                return 'usage: unlock <file> <password>'
        
        passwordVar.set(password)
        fileVar.set(file)
        
        if mode == 'lock':
            result = lock(terminalMode=True)
        elif mode == 'unlock':
            result = unlock(terminalMode=True)

        passwordVar.set('')
        fileVar.set('')
        if result is None:
            return 'success'
        return result

    def _help(self, *args):
        return """
commands:
lock <file> <password>
unlock <file> <password>
backup <recovery/dump/delete>
help"""

    def _lock(self, args):
        return self.__crypto('lock', args)
    
    def _unlock(self, args):
        return self.__crypto('unlock', args)
    
    def _backup(self, args):
        try:
            file = args[0]
            mode = args[1]
        except:
            return 'usage: backup <file> <recovery/dump/delete>'
        fileVar.set(file)
        match mode:
            case 'recovery':
                return _backup_run()
            case 'dump':
                return _backup_dump()
            case 'delete':
                if input('this will delete backup. Are you sure? (y/n)') == 'y':
                    return _backup_delete_confirm()

def _terminalHideWindow():
    """
    Скрывает окно locked, чтобы открыть терминал
    """
    try:
        root.withdraw()
    except:
        pass

def _terminalStartAdmin():
    """
    Запускает админский терминал
    """
    init(autoreset=True)
    _terminalReset()
    _terminalHideWindow()

    USERNAME = getpass.getuser()
    _keychainLogout()
    print(f'Admin terminal mode started. {Fore.LIGHTBLUE_EX}We log out from keychain for safety.{Fore.RESET}\nType {Fore.CYAN}exit{Fore.RESET} to exit terminal and return to window mode\n\
type "{Fore.CYAN}do ...{Fore.RESET}" to execute command, or "{Fore.CYAN}eval ...{Fore.RESET}" to evaluate it. you can also just enter command to evaluate it')
    while True:
        print()
        if quit_requested:
            break
        ban_found = False
        if ADMIN_TERMINAL_DESIGN == 'normal':
            inp = input(f'{Fore.LIGHTRED_EX}{USERNAME}@locked~ $ {Fore.RESET}')
        else:
            inp = input(f'{Fore.BLUE}┌──({Fore.LIGHTRED_EX}root㉿locked~{Fore.BLUE})-[{Fore.LIGHTWHITE_EX}/users/{USERNAME}{Fore.BLUE}]\n└─{Fore.LIGHTRED_EX}# {Fore.RESET}')
        result = None
        if inp in TERMINAL_EXITS:
            break
        
        for ban in BANNED_CMD:
            if ban in inp:
                print(f'{Fore.LIGHTMAGENTA_EX}Access Denied:\n{Fore.LIGHTRED_EX}{ban}{Fore.RESET} is prohibited to use in {Fore.LIGHTBLUE_EX}locked~ {Fore.RESET}terminal')
                ban_found = True
        if ban_found:
            continue
        
        safe_globals = {}

        try:
            if inp[:3] == 'do ':
                exec(inp[3:], safe_globals)
            elif inp[:5] == 'eval ':
                result = eval(inp[5:], safe_globals)
            else:
                result = eval(inp, safe_globals)

            if result:
                    print(f'{Fore.LIGHTCYAN_EX}{result}')
        except Exception as e:
            e = str(e)
            e = e.replace('(<string>, line 1)', '')
            e = e.replace('(detected at line 1)', '')
            e = e.replace('(<string>, line 0)', '')
            print(f'{Fore.RED}{e}')
    print(f'{Fore.LIGHTMAGENTA_EX}closing...')
    _terminalReset()
    root.wm_deiconify()

def _terminalStartUser():
    """
    Запускает пользовательский терминал
    """
    commandsHandler = CustomCommandsHandler()
    init(autoreset=True)
    _terminalReset()
    _terminalHideWindow()

    USERNAME = getpass.getuser()
    print(f'User terminal mode started.\nType {Fore.CYAN}exit{Fore.RESET} to exit terminal and return to window mode\n\
commands: {Fore.CYAN}lock{Fore.RESET}, {Fore.CYAN}unlock{Fore.RESET}, {Fore.CYAN}backup{Fore.RESET}')
    
    while True:
        print()
        if quit_requested:
            break
        inp = input(f'{Fore.LIGHTBLUE_EX}{USERNAME}@locked~ % {Fore.RESET}')
        if inp in TERMINAL_EXITS:
            break
        result = commandsHandler.run(inp)
        print(f'{Fore.CYAN}{result}')

    print(f'{Fore.LIGHTMAGENTA_EX}closing...')
    _terminalReset()
    root.wm_deiconify()

def _terminalChoose():
    """
    Открывает выбор терминала для открытия
    """
    _terminalReset()
    if not DEVELOPER_MODE:
        _terminalStartUser()
        return
    
    printuwu('Which terminal do u want to use?', extra=True)
    printuwu('[1] Start administrator console\n[2] Start default user console')

    root.bind('1', lambda e: _terminalStartAdmin())
    root.bind('2', lambda e: _terminalStartUser())

def _terminalReset():
    """
    Сбрасывает все бинды терминала
    """
    root.unbind('0')
    root.unbind('1')
    root.unbind('2')
    printuwu('', extra='clear')

def terminalModeAsk():
    """
    Запрашивает подтверждение намерения открыть терминал
    """
    removeFocus()
    printuwu('Open locked~ in the terminal? ', 'orange', True)
    printuwu('[0] Cancel and stay in Tkinter\n[1] Start Terminal mode')

    root.bind('0', lambda e: _terminalReset())
    root.bind('1', lambda e: _terminalChoose())


def _keychainAddFileAndPassword(file, filePassword):
    """
    Добавляет файл и пароль к нему в связку ключей, после чего сохраняет это в файл и шифрует его
    """
    keychain_autofill.append(file)
    data = _keychainDecrypt(keychain_password)
    if data == 403:
        printuwu('too many attempts. KeyChain is unavailable')
        return
    if data == False:
        if use_old_encryption:
            printuwu('ky auth failed via old encryption', 'magenta', extra=True)
            return
        showwarning('Keychain Error', 'incorrect password')
        return
    if not isinstance(data, dict):
        showwarning('Keychain Error', 'decryption returned unexpected value (1306)')
        return
    
    data[file] = filePassword

    _keychainWrite(str(data).replace("'", '"'))  # Замена одинарных кавычек на двойные 💀💀💀💀💀💀💀💀
         
    _keychainEncryptKeychain(keychain_password)

def _keychainRemoveFileAndPassword(file, keychainPassword):
    """
    Удаляет сохранёный пароль к файлу из связки ключей, и записывает обновленную связку ключей, шифруя её
    """
    try:
        keychain_autofill.remove(file)
    except:
        pass
    data = _keychainDecrypt(keychainPassword)
    if data == False:
        return 'incorrect password'
    elif data == 403:
        printuwu('too many attempts. Keychain is unavailable')
    if not isinstance(data, dict):
        showwarning('Keychain Error', 'decryption returned unexpected value (1306++)')
        return
    if file in data.keys():
        data.pop(file)
    else:
        return

    _keychainWrite(str(data).replace("'", '"'))

    _keychainEncryptKeychain(keychainPassword)

def _keychainReset():
    """
    Сбрасывает все бинды у связки ключей
    """
    global keychain_password_inputed
    try:
        root.unbind('0')
        root.unbind('1')
        root.unbind('2')
    except:
        ...

    printuwu('', extra='clear')

    try:
        root.unbind('<KeyPress>', keychain_enter_password_ID)
    except:
        ...

    keychain_password_inputed = ''

def _keychainAddCharToPassword(e):
    global skey_ky_auth_requested, skey_ky_auth_requested
    """
    Добавляет нажатую клавишу в поле ввода пароля от связки ключей в locked, а так же обрабатывает нажатия на esc, enter, delete
    """
    global keychain_password_inputed, keychain_password

    char = e.char
    keysym = e.keysym
    if keysym == 'Escape':
        _keychainReset()
        keychain_password_inputed = ''

        if skey_ky_auth_requested:
            _skeyDisable()

        skey_ky_auth_requested = False
        return
    elif keysym == 'BackSpace':
        if keychain_password_inputed:
            keychain_password_inputed = keychain_password_inputed[:-1]
        printuwu(f'{keychain_password_inputed}', 'orange')
        return
    elif keysym == 'Return':
        isPasswordExists = _keychainIsPasswordExists()
        if not isPasswordExists:
            _keychainReset()
            printuwu('create a keychain first')
        touchRequired = _touchIsEnabled()
        if touchRequired:
            touch = _touchAuth('войти в KeyChain')
            if touch == -1:
                printuwu('Touch ID is Disabled\nLock & Unlock your Mac', 'red')
                return
            elif touch == False:
                printuwu('Touch ID Failed', 'red')
                return
        
        if ky_blocked_now: 
            printuwu('too many attempts.\nKeychain is unavailable now', 'red')
            keychain_password_inputed = ''
            return

        
        if skey_ky_auth_requested and isExtraSecurityEnabled():
            printuwu('authing KeyChain', 'pink', True)
            root.update()
            decrypted_ky = _keychainDecrypt(keychain_password_inputed)
            # printuwu('', extra='clear')
        else:
            decrypted_ky = _keychainDecrypt(keychain_password_inputed)

        if _keychainSecurityLocks() == 403:
            printuwu('too many attempts.\nKeychain is unavailable now', 'red')
            keychain_password_inputed = ''
            return

        if (decrypted_ky or decrypted_ky == {}) and decrypted_ky != 403:
            keychain_password = keychain_password_inputed
            if not isinstance(decrypted_ky, dict):
                showwarning('Keychain Error', 'decryption returned unexpected value (1421)')
                return
            for key in decrypted_ky.keys():
                keychain_autofill.append(key)
            _keychainReset()
            printuwu('successfully logined into keychain')

            if skey_ky_auth_requested:
                skey_ky_auth_requested = False
                _skeyEnable()

            keychainAuthLabel.configure(fg='green')
            access('set', 'incorrect_password_attempts', '0')
        elif decrypted_ky == 403:
            printuwu('too many attempts.\nKeychain is unavailable now', 'red')
            keychain_password_inputed = ''
        else:
            printuwu(None, 'red')
            keychain_password_inputed = ''
            shakeWindow(root)
        skey_ky_auth_requested = False
        return
    
    keychain_password_inputed += char

    printuwu(f'{keychain_password_inputed}', 'orange')

def _keychainLogout():
    """
    Выходит из аккаунта связки ключей
    """
    global keychain_password
    keychain_password = None
    keychainAuthLabel.configure(fg='systemTextColor')
    if isSkeyEnabled():
        _skeyDisable()
    _keychainReset()

keychain_enter_password_ID = None  # To unbind in the future
def _keychainEnterPassword():
    """
    Запускает меню ввода пароля в locked либо предлогает разлогиниться если залогинены
    """
    global keychain_enter_password_ID
    _keychainReset()
    if _keychainLocate() is None:
        _keychainStartWindow()
        return
        
    if not _keychainIsPasswordExists():
        printuwu('Create keychain first')
        return 
    if keychain_password:
        # printuwu("Logout? It won't affect on your saved passwords", extra=True)
        # printuwu('[0] Cancel and stay logged in\n[1] Logout and dont save new passwords')
        # root.bind('0', lambda e:  _keychainReset())
        # root.bind('1', lambda e: _keychainLogout())
        _keychainLogout()
        return 
    removeFocus()
    printuwu("Enter keychain password | esc to exit", extra=True, color='orange')
    keychain_enter_password_ID = root.bind('<KeyPress>', _keychainAddCharToPassword)

def _keychainEncryptKeychain(password):
    """
    Шифрует файл связки ключей
    """

    data = _keychainGet()
    key = make_key(password)
    if data is None:
        showwarning('Keychain Error', 'keychain error: data is None')
        return 
    
    encr = encrypt_data(data, key=key)

    if isExtraSecurityEnabled():
        encr = lockExtraSecurityData(encr, password)
    _keychainWrite(encr)

def _keychainIsPasswordExists() -> bool:
    data = _keychainGet()
    if data == '{}':
        return False
    if data is None:
        _keychainCreateFilesIfNotExist()
        printuwu('Create keychain first')
        return False
    if not data[:4] == 'gAAA':  # Если начинается с этих символов, то он зашифрован
        return False
    return True
    
def _keychainSecurityWrongPasswordEntered():
    was = access('get', 'incorrect_password_attempts')
    if was is None:
        incorrect_passwords_was = 0
    else:
        incorrect_passwords_was = int(was)

    access('set', 'incorrect_password_attempts', to=str(incorrect_passwords_was+1))
    time_after_block = 10 # sec ####
    block_after_attempts = 2
    if incorrect_passwords_was+1 >= block_after_attempts:
        time_now = int(time())
        access('set', 'unblocks_at_time', str(time_now + time_after_block))

def _keychainSecurityLocks(check_status:bool=False):
    """
    Главный модуль временной блокировки keychain при вводе неверных паролей
    """
    global ky_blocked_now

    if ky_blocked_now:
        return 403
    
    

    '''
    unblocks_at_time - время в формате time.time(), когда снова можно будет ввести пароль (пройдёт время блокировки)
    если оно есть, значит блокировка активна

    incorrect_password_attempts - количество неверно введёных паролей с момента последнего ввода верного
    '''
    unblocks_at_time = access('get', 'unblocks_at_time') 
    if unblocks_at_time is None:  # если нет активной блокировки, то выходим
        return
    
    unblocks_at_time = int(unblocks_at_time) # время представляем как число секунд с какого-то момента в мире
    if time() >= unblocks_at_time: # если уже позднее, чем время, когда должна была быть разблокировка, то разблокируем (удаляем переменную)
        access('del', 'unblocks_at_time')
        ky_blocked_now = False
        return
    
    if check_status:  # если мы хотели просто проверить статус на текущий момент, то не впадаем в цикл, чтобы программа не зависла где не надо
        if access('get', 'unblocks_at_time') :
            return 403
        return
    
    if not _keychainIsKyExists():  # если не открыто окно входа в ky, то не начинаем постоянно обновлять секунды
        return 403
    
    ky_blocked_now = True

    _keychainDisableEnterPassword()
    while time() < int(unblocks_at_time):
        if quit_requested:
            return
        try:
            root.update()
        except:  ...

        try:
            ky.update()
        except:
            ...

        try:
            timee = access('get', 'unblocks_at_time')
            if timee is None:
                access('del', 'unblocks_at_time')
                ky_blocked_now = False
                break

            unblocks_at_time = int(timee)
            if unblocks_at_time - time() > 1:
                timee = access('get', 'unblocks_at_time')
                if timee is None:
                    access('del', 'unblocks_at_time')
                    ky_blocked_now = False
                    break
                _keychainPrint(f'Try again in {int(int(timee)-time())}s', 'pink')
                continue

            _keychainEnableEnterPassword()
            _keychainEnableNewPasswordLabel()
            _keychainPrint('Try again in 0s', 'pink', dontExpand=True)
            ky_blocked_now = False
            _keychainResetHeight()
            _keychainPrint(dontExpand=True)
        except:  ...

        

    access('del', 'unblocks_at_time')
    access('set', 'incorrect_password_attempts', '0')
    ky_blocked_now = False

def _keychainIsKyExists():
    try:
        ex = ky.winfo_exists()
        return ex
    except:
        return False


def _keychainGet():
    '''
    Возвращает связку ключей
    '''
    if _keychainLocate(returnBoth=False) == 'file':
        with open('auth/keychain.txt', 'r') as f:
            data = f.read()
        return data
    elif _keychainLocate(returnBoth=False) == 'access':
        data = access('get', 'keychain')
        return data

def _keychainWrite(s, mode:Literal['w', 'x']='w', where:Literal['file', 'access', 'auto']='auto'):
    if _keychainLocate(returnBoth=False) in ['file', None] or where == 'file':
        with open('auth/keychain.txt', mode) as f:
            f.write(s)
    elif _keychainLocate(returnBoth=False) == 'access' or where == 'access':
        access('set', 'keychain', s)

def _keychainGenetateID(keychain_password):
    """
    Генерирует хэш-код для связки ключей
    """
    if keychain_password is None:
        return
    decrypted = _keychainDecrypt(keychain_password)
    if decrypted == 403 or decrypted == False:
        return
    decrypted = str(decrypted)

    if decrypted is None:
        raise ConnectionRefusedError('incorrect password')
    hashs = hashlib.sha256(decrypted.encode() if isinstance(decrypted, str) else decrypted).hexdigest().upper()
    return hashs[:4] + '-' + hashs[-4:]

def _keychainMove():
    locate = _keychainLocate(returnBoth=True, notifyUserIfBoth=False)
    if locate == 'both':
        showwarning('', f'Сейчас существует одновременно две keychain, перенос в данный момент невозможен. \n\nИспользуется связка ключей из папки auth. kyID: [ {_keychainGenetateID(keychain_password) if keychain_password is not None else "Auth to View"} ]\n\n Переместите файловую связку ключей в другой место, чтобы преобразовать виртуальную в файловую')
        return
    
    if locate == 'file':
        access('set', 'keychain', _keychainGet())
        if isExtraSecurityEnabled():
            converted = _securityConvertSalt(_securityGet())
            if not isinstance(converted, str):
                showwarning('Keychain Error', 'converted format is not str (1647)')
                return
            access('set', 'keychain_security', converted)
        if _keychainLocate(returnBoth=True, notifyUserIfBoth=False) == 'both':
            _securityDelete()
            os.remove('auth/keychain.txt')
            os.rmdir("auth")
    elif locate == 'access':
        keychain = access('get', 'keychain')
        security = access('get', 'keychain_security')
        _keychainCreateFilesIfNotExist(forsed=True)
        _keychainWrite(keychain, 'x', where='file')
        if isExtraSecurityEnabled():
            converted = _securityConvertSalt(security)
            if not isinstance(converted, bytes):
                showwarning('Keychain Error', 'converted format is not str (1662)')
                return
            _securityWrite(converted, where='file')
        try: 
            with open('auth/keychain.txt'): ...
        except:
            showwarning('','FAILED MOVE ky')
            return
            
        if isExtraSecurityEnabled():
            try:
                with open('auth/security'): ...
            except:
                showwarning('','FAILED MOVE security')
                return
            else:
                access('del', 'keychain_security')
        access('del', 'keychain')
    else:
        raise

def _keychainLocate(returnBoth=True ,notifyUserIfBoth=False):
    'определяет, находится keychain в Access, в файле, или и там, и там, или её вообще нету нигде'
    acs = False
    file = False

    try:
        with open('auth/keychain.txt'): ...
    except:
        file = False
    else:
        file = True

    if access('get', 'keychain') is not None:
        acs = True
    else:
        acs = False

    if acs and not file:
        result = 'access'
    elif not acs and file:
        result = 'file'
    elif not acs and not file:
        result = None
    elif acs and file:
        result = 'both'
    else:
        raise

    if result == 'both' and notifyUserIfBoth:
        showwarning('', 'одновременно обнаружено две связки ключей. будет использоваться файловая')
    
    if result == 'both':
        return 'both' if returnBoth else 'file'

    return result

ky_blocked_now = False
def _keychainDecrypt(password, check_status_security=False) -> dict | bool | int:
    """
    Возвращает расшифрованую версию связки ключей (не расшифровывает сам файл)\\
    словарь если пароль верный\\
    False если пароль неверный\\
    403 если слишком много попыток ввода неправильного пароля
    """
    if _keychainSecurityLocks(check_status_security) == 403:
        return 403
    
    data = _keychainGet()
    if data is None:
        showwarning('Keychain Error', 'ky dont exist? (1722)')
        raise
    
    if not data[:4] == 'gAAA':  # Если начинается с этих символов, то он зашифрован
        showwarning('Keychain Error', 'this is not expected data (1727+)')
        return data # type: ignore

    if isExtraSecurityEnabled():
        data = unlockExtraSecurityData(data, password)
    decr = decrypt_data(data, key=make_key(password))
    if decr is None:
        if isExtraSecurityEnabled():
            _keychainSecurityWrongPasswordEntered()
            if _keychainSecurityLocks(check_status_security) == 403:
                return 403
        return False
    if decr == '{}':
        return {}
    decr = json.loads(decr)
    
    return decr
    
def _keychainInsertToText(s, passwordsField):
    """
    Добавляет s в поле вывода паролей
    """
    passwordsField.configure(state=NORMAL)
    passwordsField.insert(END, s)
    passwordsField.configure(state=DISABLED)

def _keychainOpenPasswords(passwords:dict):
    """
    Убирает все следы от ввода пароля и создаёт создаёт поле, в которое выводятся сохранёные пароли
    """
    kyIncorrectPasswordLabel.destroy()
    kyEnterPasswordLabel.destroy()
    kyPasswordEntry.destroy()
    kyEnterLabel.destroy()
    try:
        kyForgotPasswordLabel.destroy()
        kyNewPasswordLabel.destroy()
    except:
        pass

    passwordsField = Text(ky, state='disabled', takefocus=0)
    passwordsField.place(x=5, y=5, width=290, height=170)
    if passwords == {}:
        _keychainInsertToText('You dont have any saved passwords', passwordsField)
    for key in passwords.keys():
        if passwords[key].startswith('/sKey//'):
            s = f'{key} secured via sKey\n'
        else:
            s = f'{key} – {passwords[key]}\n'
        _keychainInsertToText(s, passwordsField)

    kyExtraSecurityLabel = Label(ky, text='Extra Security')
    kyExtraSecurityLabel.place(x=2, y=173)
    kyExtraSecurityLabel.bind("<Button-1>", lambda e: _securityOpen()) 

    kyMoveLabel = Label(ky, text='movee')
    kyMoveLabel.place(x=250, y=173)
    kyMoveLabel.bind("<Button-1>", lambda e: _keychainMove())

    _keychainResetHeight()
    access('set', 'incorrect_password_attempts', '0')
    # kyCreateRecoveryKeyLabel = Label(ky, text='create recovery key')
    # kyCreateRecoveryKeyLabel.place(x=2, y=173)
    # kyCreateRecoveryKeyLabel.bind("<Button-1>", lambda e: _keychainStartCreatingRecoveryKey()) 

def _keychainForgotPassword():
    """
    Может сбросить KeyChain если забыт пароль
    """
    if askyesno('', 'it is impossible to recover your password. You can delete all your keychain and create a new one, or continue trying passwords.\nDELETE KEYCHAIN AND SET UP NEW?'):
        try:
            kyNewPasswordEntry.destroy()
            kyEnterNewLabel.destroy()
            kyCurrentLabel.destroy()
            kyNewLabel.destroy()
        except:
            ...

        _keychainWrite("{}")

        if isExtraSecurityEnabled():
            _securityDelete()

        try:  keyring.delete_password('LOCKED', 'OK_PASSWORD_TIME')
        except:  pass

        try: keyring.delete_password("LOCKED", 'TOUCH_ID')
        except: pass
        ky.unbind('<Return>')
        kyPasswordEntry.delete(0, END)
        kyEnterPasswordLabel.configure(text='Create your ky password')
        ky.bind('<Return>', lambda e: _keychainAuth(kypasswordVar.get()))
    ky.focus()
    kyPasswordEntry.focus()

ky_newpassword_disabled = False
def _keychainDisableNewPasswordLabel():
    '''
    Отключает кнопку для начала смены пароля (New password)
    '''
    global ky_newpassword_disabled
    if ky_newpassword_disabled: return
    kyNewPasswordLabel.configure(state=DISABLED)
    kyNewPasswordLabel.unbind('<Button-1>', kyNewPasswordLabel_ID)
    ky_newpassword_disabled = True

def _keychainEnableNewPasswordLabel():
    global kyNewPasswordLabel_ID, ky_newpassword_disabled
    if not ky_newpassword_disabled: return
    kyNewPasswordLabel_ID = kyNewPasswordLabel.bind("<Button-1>", lambda e: _keychainStartChangingPassword())
    kyNewPasswordLabel.configure(state=NORMAL)
    ky_newpassword_disabled = False

def _keychainDisableEnterPassword(silent:bool=False):
    try:
        ky.unbind('<Return>', ky_ID_enter_password)
        if not silent:
            kyEnterLabel.configure(state=DISABLED)
    except:
        pass

def _keychainEnableEnterPassword(silent:bool=False):
    global ky_ID_enter_password
    try:
        ky_ID_enter_password = ky.bind('<Return>', lambda e: _keychainAuth(kypasswordVar.get()))
        if not silent:
            kyEnterLabel.configure(state=NORMAL)
    except:
        pass
def _keychainStartChangingPassword():
    """
    Создаёт обстановку для смены пароля
    """
    if _touchIsEnabled():
        touch = _touchAuth('изменить пароль от KeyChain')
        if touch == False:
            _keychainPrint('Touch ID Failed', 'red', True)
            return
        elif touch == -1:
            _keychainPrint('Unable to Use Touch ID', 'red', True)
            return

    global kyNewPasswordEntry, kyEnterNewLabel, kyCurrentLabel, kyNewLabel
    kyNewPasswordEntry = Entry(ky, justify='center')
    kyNewPasswordEntry.place(x=53, y=105)
    kyIncorrectPasswordLabel.configure(text=' ')

    _keychainDisableNewPasswordLabel()

    kyEnterPasswordLabel.configure(text='Create a new password')

    kyEnterNewLabel = Label(ky, text='↩')
    kyEnterNewLabel.place(x=250, y=108)

    kyCurrentLabel = Label(ky, text='current')
    kyCurrentLabel.place(x=5, y=77)

    kyNewLabel = Label(ky, text='new')
    kyNewLabel.place(x=14, y=105)
    ky.unbind('<Return>')
    ky.bind('<Return>', lambda e: _keychainChangePassword(current=kypasswordVar.get(), new=kyNewPasswordEntry.get()))

    _keychainResetHeight()

def _keychainChangePassword(current, new):
    """
    Меняет пароль с current на new
    """
    try:
        Fernet(make_key(new))
    except:
        _keychainPrint('bad new password', 'pink')
        return
    decrypted_ky = _keychainDecrypt(current)
    if decrypted_ky == {} or decrypted_ky and decrypted_ky != 403:
        data = decrypted_ky
        _keychainWrite(str(data).replace("'", '"'))
        _keychainEncryptKeychain(new)
        _keychainAuth(new, just_changed=True)
    elif decrypted_ky == 403:
        _keychainPrint('Try again later. Something went wrong.\nYou shouldnt see this message normally', 'red')
    else:
        _keychainPrint('incorrect current password', 'pink')
    
def _keychainAuth(password, just_changed:bool=False):
    """
    Запускает процесс авторизации. Проверяет пароль: если он верный, то открывает окно с паролями
    """
    touchRequired = _touchIsEnabled()
    if not just_changed:
        if touchRequired:
            touch = _touchAuth('открыть KeyChain')
            if touch == -1:
                _keychainPrint('Touch ID is Disabled: Lock & Unlock your Mac', 'red', aboutTouch=True)
                ky.focus()
                kyPasswordEntry.focus()
                return 'fail'

            elif touch == False:
                if keychain_password:
                    printuwu('Touch ID Failed', 'pink')
                    ky.destroy()
                    return 'fail'
                _keychainPrint('Touch ID Failed', 'red', True)
                return 'fail'
                
            
    isPasswordExists = _keychainIsPasswordExists()
    if not isPasswordExists:
        _keychainEncryptKeychain(password)

    decrypted_ky = _keychainDecrypt(password)
    if decrypted_ky == {} and isinstance(decrypted_ky, dict):
        _keychainOpenPasswords(decrypted_ky)
    elif decrypted_ky == 403:
        kyPasswordEntry.delete(0, END)
        _keychainSecurityLocks()
    elif decrypted_ky and isinstance(decrypted_ky, dict):
        _keychainOpenPasswords(decrypted_ky)
    
    else:
        kyPasswordEntry.delete(0, END)
        kyIncorrectPasswordLabel.configure(text='incorrect password')
        if ky_printed_about_touchid:
            _keychainResetHeight()
            _keychainPrint(dontExpand=True)  # clear
            
def _keychainCreateFilesIfNotExist(forsed=False):
    '''
    Создаёт файлы для связки ключей если их нет, но не шифрует в конце
    forced - создать, даже если файлы уже возможно существуют
    '''
    if not forsed:
        if _keychainLocate() == 'access':
            return
    if not os.path.exists('auth'):
        os.makedirs('auth')

    try:
        with open('auth/keychain.txt'): ...
    except:
        _keychainWrite('{}', 'x')

def _keychainShowkyID():
    """
    Показывает kyID
    """
    if keychain_password:
        _keychainPrint(f'kyID: {_keychainGenetateID(keychain_password)}', 'magenta')
    else:
        _keychainPrint('Auth to View', 'magenta')



ky_ID_enter_password = None
def _keychainStartWindow():
    """
    Запускает окно связки ключей поверх основного окна
    """
    global kyIncorrectPasswordLabel, kyEnterPasswordLabel, kyPasswordEntry, kyEnterLabel, ky, kyForgotPasswordLabel, kypasswordVar, kyNewPasswordLabel, kyInfoLabel, ky_expanded_already, kyNewPasswordLabel_ID, ky_ID_enter_password
    _keychainReset()
    
    ky = Tk() 
    kyMenu= Menu(ky)
    kyMenuAdvanced = Menu(ky)
    kyMenuAdvanced.add_command(label='Показать kyID', command=_keychainShowkyID)

    kyMenu.add_cascade(label='Advanced', menu=kyMenuAdvanced)
    ky.config(menu=kyMenu)
    ky.geometry('300x200')
    # ky.eval('tk::PlaceWindow . center')
    # centerwindow(ky)
    # ky.update_idletasks()
    if keychain_password and isExtraSecurityEnabled():
        ky.title('Authing Extra Security...')
    else:
        ky.title(' ')
    ky.resizable(False, False)
    
    # ky.eval('tk::PlaceWindow . center')
    # centerwindow(ky)
    # ky.update()
    # ky.update_idletasks()
    # ky.after(5)
    centerwindow(ky)
    ky.attributes('-topmost', 1)  # Помещает окно на передний план
    if isExtraSecurityEnabled():
        ky.after(15, lambda: None)
    ky.update()
    ky.attributes('-topmost', 0) 

    # ky.update()
    # ky.focus()
    if isExtraSecurityEnabled():
        root.update()
    _keychainCreateFilesIfNotExist()
    isPasswordExists = _keychainIsPasswordExists()
    if not isPasswordExists:
        kyEnterPasswordLabel = Label(ky, text='Create your ky password')
    else:
        kyEnterPasswordLabel = Label(ky, text='Enter your ky password')
    kyEnterPasswordLabel.place(x=76, y=50)

    kyIncorrectPasswordLabel = Label(ky, justify='center')
    kyIncorrectPasswordLabel.place(x=89, y=100)

    kypasswordVar = StringVar(ky)
    kypasswordVar.trace_add('write', lambda *args: kyIncorrectPasswordLabel.configure(text=' '))

    kyPasswordEntry = Entry(ky, textvariable=kypasswordVar, show='·', justify='center')
    kyPasswordEntry.place(x=53, y=75)

    kyEnterLabel = Label(ky, text='↩')
    kyEnterLabel.place(x=250, y=78)

    kyInfoLabel = Label(ky, text='')
    kyInfoLabel.place(x=2, y=200)

    ky_expanded_already = False

    if isPasswordExists:
        kyNewPasswordLabel = Label(ky, text='New password')
        kyNewPasswordLabel.place(x=3, y=175)
        kyNewPasswordLabel_ID = kyNewPasswordLabel.bind("<Button-1>", lambda e: _keychainStartChangingPassword()) 

        kyForgotPasswordLabel = Label(ky, text='forgot?')
        kyForgotPasswordLabel.place(x=247, y=175)
        kyForgotPasswordLabel.bind("<Button-1>", lambda e: _keychainForgotPassword()) 
    kyPasswordEntry.focus()

    if not _touchCheck():
        _keychainPrint('Touch ID is Disabled: Lock & Unlock your Mac', 'red', aboutTouch=True)

    if keychain_password:
        ky.title('KeyChain')
        # ky.eval('tk::PlaceWindow . center')
        # centerwindow(ky)
        # ky.update()
        # ky.after(1)
        res = _keychainAuth(keychain_password)
        if res == 'fail':
            return
    
    _keychainSecurityLocks()
    ky.bind('<Escape>', lambda e: ky.destroy())
    ky_ID_enter_password = ky.bind('<Return>', lambda e: _keychainAuth(kypasswordVar.get()))

ky_printed_about_touchid = False
def _keychainPrint(text='', color:str|None=None, aboutTouch:bool=False, dontExpand:bool=False):
    global ky_printed_about_touchid

    ky_printed_about_touchid = aboutTouch
    
    kyInfoLabel.configure(fg='white')
    kyInfoLabel.configure(text=text)
    if color:
        kyInfoLabel.configure(fg=color)

    if not dontExpand:
        _keychainExpandHeight()

ky_expanding_now = False
ky_expanded_already = False
height_to_expand = 23
def _keychainExpandHeight():
    global ky_expanded_already, ky_expanding_now

    if ky_expanding_now or ky_expanded_already:
        return
    
    ky_expanding_now = True
    ky_expanded_already = True

    width = ky.winfo_width()
    height = ky.winfo_height()
    x = ky.winfo_x()
    y = ky.winfo_y()

    for i in range(height_to_expand):
        height += 1

        if height == height + height_to_expand:
            break

        ky.geometry(f'{width}x{height}+{x}+{y}')
        ky.update()
    ky_expanding_now = False

def _keychainResetHeight():
    global ky_expanded_already, ky_expanding_now

    if ky_expanding_now:
        return
    if not ky_expanded_already:
        return
    
    ky_expanding_now = True
    ky_expanded_already = False

    width = ky.winfo_width()
    height = ky.winfo_height()
    x = ky.winfo_x()
    y = ky.winfo_y()

    for i in range(height_to_expand):
        if height == 200:
            break
        height -= 1

        

        ky.geometry(f'{width}x{height}+{x}+{y}')
        ky.update()
    ky_expanding_now = False

def keychainCheckKyPassword(kypassword):
    """
    Checks the provided keychain password by attempting to decrypt it.

    Args:
        kypassword (str): The keychain password to be checked.

    Returns:
        int: Returns 403 if the decryption fails with a 403 error.
        bool: Returns True if the decryption is successful or if the decrypted ky is an empty dictionary.
              Returns False if the decryption fails with any other error.
    """
    decrypted_ky = _keychainDecrypt(kypassword, True)
    if decrypted_ky == 403:
        return 403
    if decrypted_ky == {}:
        return True
    elif decrypted_ky:
        return True
    return False

def _touchCheck() -> bool:
    from LocalAuthentication import LAContext # type: ignore
    from LocalAuthentication import LAPolicyDeviceOwnerAuthenticationWithBiometrics # type: ignore

    kTouchIdPolicy = LAPolicyDeviceOwnerAuthenticationWithBiometrics

    c = ctypes.cdll.LoadLibrary(None) # type: ignore

    dispatch_semaphore_create = c.dispatch_semaphore_create
    dispatch_semaphore_create.restype = ctypes.c_void_p
    dispatch_semaphore_create.argtypes = [ctypes.c_int]

    dispatch_semaphore_wait = c.dispatch_semaphore_wait
    dispatch_semaphore_wait.restype = ctypes.c_long
    dispatch_semaphore_wait.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

    dispatch_semaphore_signal = c.dispatch_semaphore_signal
    dispatch_semaphore_signal.restype = ctypes.c_long
    dispatch_semaphore_signal.argtypes = [ctypes.c_void_p]

    context = LAContext.new()

    can_evaluate = context.canEvaluatePolicy_error_(kTouchIdPolicy, None)[0]
    if can_evaluate:
        return True
    return False


def _touchAuth(desc) -> bool|int:
    """
    return:
    \\-1: unable to use Touch ID
    True: successful
    False: failed
    """
    from LocalAuthentication import LAContext # type: ignore
    from LocalAuthentication import LAPolicyDeviceOwnerAuthenticationWithBiometrics # type: ignore

    kTouchIdPolicy = LAPolicyDeviceOwnerAuthenticationWithBiometrics

    c = ctypes.cdll.LoadLibrary(None) # type: ignore

    DISPATCH_TIME_FOREVER = sys.maxsize

    dispatch_semaphore_create = c.dispatch_semaphore_create
    dispatch_semaphore_create.restype = ctypes.c_void_p
    dispatch_semaphore_create.argtypes = [ctypes.c_int]

    dispatch_semaphore_wait = c.dispatch_semaphore_wait
    dispatch_semaphore_wait.restype = ctypes.c_long
    dispatch_semaphore_wait.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

    dispatch_semaphore_signal = c.dispatch_semaphore_signal
    dispatch_semaphore_signal.restype = ctypes.c_long
    dispatch_semaphore_signal.argtypes = [ctypes.c_void_p]

    context = LAContext.new()

    can_evaluate = context.canEvaluatePolicy_error_(kTouchIdPolicy, None)[0]
    if not can_evaluate:
        return -1

    sema = dispatch_semaphore_create(0)

    # we can't reassign objects from another scope, but we can modify them
    res = {'success': False, 'error': None}

    def cb(_success, _error):
        res['success'] = _success
        if _error:
            res['error'] = _error.localizedDescription()
        dispatch_semaphore_signal(sema)

    context.evaluatePolicy_localizedReason_reply_(kTouchIdPolicy, desc, cb)
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER)

    if res['error']:
        return False
    return True

def _touchEnable(se):
    if _touchIsEnabled():
        print('enabled already')
        return
    
    auth = _touchAuth('запрашивать Touch ID для важных действий над KeyChain')
    if auth == -1:
        _securityPrintInfo('Unable to Use Touch ID.\nLock & Unlock your Mac', 'pink')
    elif auth == False:
        _securityPrintInfo('Touch ID Failed', 'red')
    elif auth == True:
        keyring.set_password('LOCKED', 'TOUCH_ID', '1')
        seTouchIdEnableButton.destroy()
        seTouchIdDisableButton = Button(se, text='Disable Touch ID', fg='red', command=lambda:_touchDisable(se), takefocus=0)
        seTouchIdDisableButton.place(x=182, y=145, width=120)
        _securityPrintInfo("")

def _touchDisable(se):
    if not _touchIsEnabled():
        print('disabled already')
        return
    
    auth = _touchAuth('перестать запрашивать Touch ID для важных действий над KeyChain')
    if auth == -1:
        _securityPrintInfo('Unable to Use Touch ID.\nLock & Unlock your Mac', 'pink')
    elif auth == False:
        _securityPrintInfo('Touch ID Failed', 'red')
    elif auth == True:
        keyring.delete_password('LOCKED', 'TOUCH_ID')
        seTouchIdDisableButton.destroy()
        seTouchIdEnableButton = Button(se, text='Enable Touch ID', fg='magenta', command=lambda:_touchEnable(se))
        seTouchIdEnableButton.place(x=182, y=145, width=120)
        _securityPrintInfo("")

def _touchIsEnabled() -> bool:
    istouch = keyring.get_password('LOCKED', 'TOUCH_ID')
    if istouch == None:
        return False
    return True

def _securityConvertSalt(s):
    'конвертирует формат соли из байтов в строку и обратно, чтобы была возможность хранить её в access'
    if type(s) == bytes:
        token = b64encode(s).decode()
        return token
    elif type(s) == str:
        return b64decode(s)
    showwarning('','converting failed: unexpected type')
    raise

def _securityGet():
    "Получить ключ security"
    if _keychainLocate(returnBoth=False) == 'file':
        with open('auth/security', 'rb') as f:
            salt = f.read()
            return salt
        
    elif _keychainLocate(returnBoth=False) == 'access':
        salt = access('get', 'keychain_security')
        return _securityConvertSalt(salt)
    raise


def _securityWrite(salt:bytes, where:Literal['file', 'access', 'auto']='auto'):
    "Записать ключ в security"
    if _keychainLocate(returnBoth=False) == 'file' or where == 'file':
        with open('auth/security', 'xb') as f:
            f.write(salt)

    elif _keychainLocate(returnBoth=False) == 'access' or where == 'access':
        converted = _securityConvertSalt(salt)
        if isinstance(converted, (bytearray, bytes, memoryview)):
            showwarning('','converting failed (2295)')
            return
        access('set', 'keychain_security', converted)

    else:
        raise

def _securityDelete():
    'Удаляет ключ security'
    try:
        if _keychainLocate(returnBoth=False) == 'file':
            os.remove('auth/security')
        elif _keychainLocate(returnBoth=False) == 'access':
            access('del', 'keychain_security')
    except:
        pass
def _securityPrintInfo(s, color:str|None=None, clear=False):
    seInfoLabel.configure(fg='systemTextColor')

    if clear:
        seInfoLabel.configure(text='')
        return
    seInfoLabel.configure(text=str(s))
    if color is not None:
        seInfoLabel.configure(fg=color)

def _securityOpen(e=None):
    global seSecurityEnabledLabel, seDisableButton, seSecurityDisabledLabel, seEnableButton, seKyPasswordEntry, seInfoLabel,\
    seTouchIdDisableButton, seTouchIdEnableButton, securityHelpOpened
    se = Tk()
    seMenu = Menu(se)
    se.config(menu=seMenu)
    se.geometry('300x200')
    se.title(' ')
    se.resizable(False, False)
    centerwindow(se)
    Label(se, text='Welcome to ExtraSecurity mode', font='Arial 20').pack()
    Button(se, text='what is it?', command=lambda: _securityShowHelp(se), takefocus=0).place(x=216, y=172, width=87)

    seEnabled = isExtraSecurityEnabled()
    touchIdEnabled = _touchIsEnabled()

    securityHelpOpened = False

    seSecurityEnabledLabel = Label(se, text='ExtraSecurity is enabled', fg='lime', font='Arial 15')
    seDisableButton = Button(se, text='DISABLE', fg='red', command=lambda:_securityDisable(se=se), takefocus=0)
    seSecurityDisabledLabel = Label(se, text='ExtraSecurity is disabled', font='Arial 15', fg='pink')
    seEnableButton = Button(se, text='ENABLE', fg='magenta', command=lambda:_securityEnable(se=se), takefocus=0)
    seInfoLabel = Label(se, text='', justify='left')
    seInfoLabel.place(x=0, y=125)

    seTouchIdEnableButton = Button(se, text='Enable Touch ID', fg='magenta', command=lambda:_touchEnable(se), takefocus=0)
    seTouchIdDisableButton = Button(se, text='Disable Touch ID', fg='red', command=lambda:_touchDisable(se), takefocus=0)

    seHelpLabel = Label(se, text='Extra Security for KeyChain позволяет\nсущественно затруднить взлом, требуя\nбольше времени на попытку пароля', fg='magenta', justify='left')
    seHelpLabel.place(x=0, y=200)

    if not keychain_password:
        seSecret = Label(se, text='↩', fg='#ffc0cb')
        seSecret.place(x=280, y=233)
        seSecret.bind("<Button-1>", lambda e: _securityRunCode(se))

    if not keychain_password:
        seNotLoginedLabel = Label(se, text='You are not authed.\nEnter ky password to make actions:', justify='left', fg='orange')
        seNotLoginedLabel.place(x=0, y=60)

        seKyPasswordEntry = Entry(se)
        seKyPasswordEntry.place(x=0, y=100)
        seKyPasswordEntry.focus()

    if touchIdEnabled:
        seTouchIdDisableButton.place(x=182, y=145, width=120)
    else:
        seTouchIdEnableButton.place(x=182, y=145, width=120)

    if seEnabled:
        seSecurityEnabledLabel.place(x=68, y=30)
        seDisableButton.place(x=0, y=172, width=220)
    else: 
        seSecurityDisabledLabel.place(x=61, y=30)
        seEnableButton.place(x=0, y=172, width=220)

    se.bind('<Escape>', lambda e: se.destroy())

def _securityRunCode(se):
    code = f'{seKyPasswordEntry.get()[2:]}'
    if not seKyPasswordEntry.get().startswith('//'):
        return
    
    match code:
        case 'uwu':
            _securityPrintInfo("        *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚\n", 'pink')
        # case 'touch':
        #     _touchAuth('добавить новый отпечаток пальца учётной записи Thekoteyka')

securityHelpOpened = False
start_se_height = None
opening_se_now = False
def _securityShowHelp(se:Tk):
    global securityHelpOpened, start_se_height, opening_se_now

    if opening_se_now:
        return
    opening_se_now = True

    securityHelpOpened = False if securityHelpOpened else True
    width = se.winfo_width()
    height = se.winfo_height()

    start_se_height = height if start_se_height is None else start_se_height

    x = se.winfo_x()
    y = se.winfo_y()

    added_height = 53

    for i in range(added_height):
        if securityHelpOpened:
            height += 1

            if height == start_se_height + added_height:
                break
        else:
            height -= 1

            if height == start_se_height:
                break

        se.geometry(f'{width}x{height}+{x}+{y}')
        root.update()
        root.update()
    opening_se_now = False

def _securityDisable(se:Tk):
    global seSecurityEnabledLabel, seDisableButton, seSecurityDisabledLabel, seEnableButton
    password = keychain_password
    seDisableButton.configure(command='')
    se.update()
    if not password:
        if not seKyPasswordEntry.get():
            _securityPrintInfo('Input your ky password', 'red')
            se.focus()
            seKyPasswordEntry.focus()
            return
        else:
            password = seKyPasswordEntry.get()
    if se:
        _securityPrintInfo('Verifying...', 'magenta')
        se.update()
    check =  keychainCheckKyPassword(password)

    if check == 403:
        _securityPrintInfo('too many attempts.\ntry again later', 'red')
        seDisableButton.configure(command=lambda:_securityDisable(se=se))
        return
    if not check:
        _securityPrintInfo('incorrect password', 'red')
        seDisableButton.configure(command=lambda:_securityDisable(se=se))
        seKyPasswordEntry.focus()
        # _keychainSecurityWrongPasswordEntered()
        return


    if not isExtraSecurityEnabled():
        showwarning('', 'ALERT: 2 at ExtraSecurity dont enabled')
        return
    if se:
        _securityPrintInfo('Disabling...', 'magenta')
        se.update()

    kydata = _keychainGet()
    unlockedData = unlockExtraSecurityData(kydata, password)

    if not unlockedData:
        showwarning('', 'ALERT: 3 at no unlocked data')
        return
    
    _keychainWrite(unlockedData)
    _securityDelete()
    if se:
        seSecurityDisabledLabel = Label(se, text='ExtraSecurity is disabled', font='Arial 15', fg='pink')
        seEnableButton = Button(se, text='ENABLE', fg='magenta', command=lambda:_securityEnable(se=se))
        
        seSecurityEnabledLabel.destroy()
        seDisableButton.destroy()
        seSecurityDisabledLabel.place(x=61, y=30)
        seEnableButton.place(x=0, y=172, width=220)

        _securityPrintInfo('')

def _securityEnable(se:Tk):
    global seSecurityEnabledLabel, seDisableButton, seSecurityDisabledLabel, seEnableButton

    password = keychain_password
    seEnableButton.configure(command='')
    if not password:
        if not seKyPasswordEntry.get():
            _securityPrintInfo('Input your ky password', 'red')
            seEnableButton.configure(command=lambda:_securityEnable(se=se))
            se.focus()
            seKyPasswordEntry.focus()
            return
        else:
            password = seKyPasswordEntry.get()
    
    if not keychainCheckKyPassword(password):
        _securityPrintInfo('incorrect password', 'red')
        se.focus()
        seKyPasswordEntry.focus()
        seEnableButton.configure(command=lambda:_securityEnable(se=se))
        return
    
    salt = os.urandom(128)

    try:
        open('auth/security')
    except:
        pass
    else:
        showwarning('', 'ALERT: -1 at ExtraSecurity file already exists in [def _securityEnable]')
        return
    
    _securityWrite(salt)

    kydata = _keychainGet()

    if se:
        _securityPrintInfo('Enabling...', 'magenta')
        se.update()

    lockedData = lockExtraSecurityData(kydata, password)
    if not lockedData:
        showwarning('', 'ALERT: 1 at no lockedData in [def _securityEnable]\n!keychain might be damaged')
        return
    
    _keychainWrite(lockedData)

    if se:
        seSecurityEnabledLabel = Label(se, text='ExtraSecurity is enabled', fg='lime', font='Arial 15')
        seDisableButton = Button(se, text='DISABLE', fg='red', command=lambda:_securityDisable(se=se))

        seSecurityDisabledLabel.destroy()
        seEnableButton.destroy()
        seSecurityEnabledLabel.place(x=68, y=30)
        seDisableButton.place(x=0, y=172, width=220)
        _securityPrintInfo('')

def _securityCreateNewKey(kypassword, salt):
    newkey = hashlib.pbkdf2_hmac(
        'sha256',
        str(kypassword).encode('utf-8'),
        salt,
        7_000_000
    )
    newkey = str(newkey)
    newkey = ''.join(e for e in newkey if e.isalnum()) # убрать специальные символы типо " \ ' 
    return newkey

def unlockExtraSecurityData(data, kypassword:str):
    if not isExtraSecurityEnabled():
        return
    

    salt = _securityGet()
    newkey = _securityCreateNewKey(kypassword, salt)
    decr = decrypt_data(data, key=make_key(newkey))
    return decr

def lockExtraSecurityData(data, kypassword:str):
    if not isExtraSecurityEnabled():
        return
    
    salt = _securityGet()
    newkey = _securityCreateNewKey(kypassword, salt)
    enc = encrypt_data(data, key=make_key(newkey))
    return enc

def isExtraSecurityEnabled() -> bool:
    try:
        open('auth/security', 'rb')
    except:
        return True if access('get', 'keychain_security') else False
    else:
        return True

def _skeyCreate():
    key = Fernet.generate_key().decode()
    key = f'/sKey//{key[7:]}'
    return key

def _skeyEnable():
    global skeyLabel, skey_ky_auth_requested
    if not keychain_password:
        _keychainEnterPassword()
        printuwu('enter ky password to enable sKey | esc to exit', extra=True, color='orange')
        skey_ky_auth_requested = True
        return
    
    passwordEntry.delete(0, END)
    passwordEntry['state'] = DISABLED
    passwordEntry['fg'] = 'systemWindowBackgroundColor'
    passwordEntry['show'] = ' '
    
    if fileVar.get():
        if isExtraSecurityEnabled():
            printuwu('enabling sKey...', 'pink', extra=True)
            root.update()
            keychainFiles = _keychainDecrypt(keychain_password)
            printuwu('', extra='clearextra')
        else:
            keychainFiles = _keychainDecrypt(keychain_password)

        if not isinstance(keychainFiles, dict): 
            printuwu('sKey failed', 'red', extra=True)
            return
        
        if fileVar.get() in keychainFiles:
            passwordVar.set(keychainFiles[fileVar.get()])

    access('set', 'SKEY-STATE', 'on')

    skeyLabel['text'] = 'sKey on'
    skeyLabel['fg'] = 'lime'
    skeyLabel.bind("<Button-1>", lambda e: _skeyDisable()) 
    
def _skeyDisable():
    global skeyLabel

    passwordEntry['state'] = NORMAL
    passwordEntry.delete(0, END)
    passwordEntry['show'] = ''

    passwordEntry['fg'] = 'systemWindowBackgroundColor'
    
    access('set', 'SKEY-STATE', 'off')

    skeyLabel['text'] = 'sKey off'
    skeyLabel['fg'] = 'pink'
    skeyLabel.bind("<Button-1>", lambda e: _skeyEnable())

def isSkeyEnabled():
    if access('get', 'SKEY-STATE') == 'on':
        return True
    return False

def disablepasswordEntry():
    passwordEntry['state'] = DISABLED

def enablepasswordEntry():
    passwordEntry['state'] = NORMAL

confirmed_use_forcfully:bool = False
def useForcfully(what:Literal['lock', 'unlock']):
    global confirmed_use_forcfully

    if not confirmed_use_forcfully:
        if askyesno('', 'Вы собираетесь совершить действие принудительно, это может привести к необратимым последствиям.\nВы уверены?'):
            confirmed_use_forcfully = True

    match what:
        case 'lock':
            lock(forced=True)
        case 'unlock':
            unlock(forced=True)

    

use_old_encryption:bool = False
def useOldEncryption():
    global use_old_encryption
    use_old_encryption = True
    menuAdvanced.entryconfig('Использовать старое шифрование до закрытия', state="disabled")
    menuAdvanced.add_cascade(label='Использовать новое шифрование', command=useNewEncryption)
    root.title('using old encryption')
    _keychainLogout()
    updPasswordEntryColor()

def useNewEncryption():
    global use_old_encryption
    use_old_encryption = False
    menuAdvanced.entryconfig('Использовать старое шифрование до закрытия', state="normal")
    menuAdvanced.delete('Использовать новое шифрование')
    root.title('')
    _keychainLogout()
    updPasswordEntryColor()


ACCESSES = Literal['SKEY-STATE', 'unblocks_at_time', 'incorrect_password_attempts', 'keychain', 'keychain_security']
def access(mode:Literal['get', 'set', 'del'], var:ACCESSES, to:str|None=None):
    """Доступ к постоянным переменным, которые доступны даже после перезагрузки пк

SKEY-STATE [ on | off | auth ] - состояние sKey \\
unblocks_at_time [str] - время (в time()), когда можно будет разблокировать KeyChain при включенной ExtraSecurity \\
incorrect_password_attempts [int] - количество неверных попыток ввода пароля при включенной ExtraSecurity \\
keychain [str] - зашифрованный keychain при хранении в access \\
keychain_security [str] - ключ ExtraSecurity (соль) при хранении в access \\
"""
    if mode == 'get':
        return keyring.get_password('LOCKED', var)
    elif mode == 'set':
        if to is None:
            showwarning('', '"to" is required for SET mode')
            return
        keyring.set_password('LOCKED', var, to)
    elif mode == 'del':
        keyring.delete_password('LOCKED', var)

def accessGet(variable:ACCESSES):
    return access('get', variable)

def accessSet(variable:ACCESSES, to:str):
    access('set', variable, to)

def accessDel(variable:ACCESSES):
    access('del', variable)

def shakeWindow(win):
    """Функция для плавной тряски окна"""
    # Настройки тряски
    initial_amplitude = 40  # Начальная амплитуда (пиксели)
    damping_factor = 0.30  # Коэффициент затухания (уменьшение амплитуды)
    steps_per_cycle = 10  # Количество шагов на цикл
    total_cycles = 3  # Общее количество циклов

    base_x = win.winfo_x()
    base_y = win.winfo_y()

    def animate(step, amplitude):
        # Вычисляем смещение с использованием синусоидального эффекта
        angle = (step % steps_per_cycle) / steps_per_cycle * 2 * math.pi
        offset = int(amplitude * math.sin(angle))
        
        # Перемещаем окно
        win.geometry(f"+{base_x + offset}+{base_y}")
        
        # Проверяем, нужно ли продолжать
        if step < total_cycles * steps_per_cycle:
            # Уменьшаем амплитуду в начале каждого нового цикла
            if step % steps_per_cycle == 0:
                amplitude *= damping_factor
            win.after(16, lambda: animate(step + 1, amplitude))  # 16 мс для ~60 FPS
        else:
            # Возвращаем окно в исходное положение
            win.geometry(f"+{base_x}+{base_y}")

    # Начинаем анимацию с шага 0
    animate(0, initial_amplitude)

def centerwindow(win):
    """
    💀💀💀💀💀💀💀💀💀💀💀
    центрирует окно ткинтер
    """
    win.update_idletasks()
    width = win.winfo_width()
    frm_width = win.winfo_rootx() - win.winfo_x()
    win_width = width + 2 * frm_width
    height = win.winfo_height()
    titlebar_height = win.winfo_rooty() - win.winfo_y()
    win_height = height + titlebar_height + frm_width
    x = win.winfo_screenwidth() // 2 - win_width // 2
    y = win.winfo_screenheight() // 2 - win_height // 2
    win.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    win.deiconify()


root = Tk()

root.geometry('300x200')
root.eval('tk::PlaceWindow . center')
centerwindow(root)
root.title(' ')
root.resizable(False, False)
# root.after(50)
# root.iconify()
# root.update()

fileVar = StringVar(root)
passwordVar = StringVar(root)

autofillLabel = Label(root, fg='#ffc0cb', font='Arial 12', justify='left')
autofillLabel.place(x=250, y=56)

Button(root, text='lock', command=lock, takefocus=0).place(x=5, y=120)
Button(root, text='unlock', command=unlock, takefocus=0).place(x=220, y=120)

nameLabel = Label(root, text='name')
nameLabel.place(x=5, y=63)
nameLabel.bind("<Button-1>", lambda e: colsoleOpenAks())

Label(root, text='passwrd').place(x=5, y=93)

fileEntry = Entry(root, textvariable=fileVar)
fileEntry.place(x=60, y=60)
fileVar.trace_add('write', updFileEntryColor)  # При записи каждой новой буквы вызываетя обновление цвета для имени файла

passwordEntry = Entry(root, textvariable=passwordVar, fg='red')
passwordEntry.place(x=60, y=90)
passwordVar.trace_add('write', updPasswordEntryColor)  # аналогично

OutputLabel = Label(root, text='', justify='left')
OutputLabel.place(x=5, y=160)

ExtraOutputLabel = Label(root, text='', justify='left', font='Arial 12')
ExtraOutputLabel.place(x=5, y=146)

quit_requested = False
def exiting_now(e=None):
    global ky_blocked_now, quit_requested
    ky_blocked_now = False
    quit_requested = True
    _keychainSecurityLocks(check_status=True)
    root.quit()
    if _keychainIsKyExists():
        ky.quit()

root.createcommand("tk::mac::Quit" , exiting_now)
root.protocol("WM_DELETE_WINDOW", exiting_now)

root.bind('<Tab>', lambda e: autofill('replace'))
root.bind('<Control_L>', lambda e: insertTestPassword())
root.bind('<Alt_L>', lambda e: root.focus())


if sys.platform == "win32":
    showwarning('', 'App is not designed for Windows system. You will experience problems')

keychainAuthLabel = Label(root, text='auth ky')
keychainAuthLabel.place(x=0, y=0)
keychainAuthLabel.bind("<Button-1>", lambda e: _keychainEnterPassword()) 

keychainOpenLabel = Label(root, text='open ky')
keychainOpenLabel.place(x=0, y=20)
keychainOpenLabel.bind("<Button-1>", lambda e: _keychainStartWindow()) 

lockedLabel = Label(root, text='locked~')
lockedLabel.pack()

helpLabel = Label(root, text='?', relief='flat')
helpLabel.place(x=281, y=174)
helpLabel.bind("<Button-1>", lambda e: menuHelp.post(e.x_root, e.y_root))  # При нажатии на вопрос
helpLabel.bind("<Button-2>", lambda e: backupFile())
helpLabel.bind("<Enter>", lambda e: lockedLabel.configure(text='click to show help\nr click to backup'))  # При наведении на вопрос
helpLabel.bind("<Leave>", lambda e: lockedLabel.configure(text='locked~'))  # При уведении курсора с вопроса
  




root.option_add("*tearOff", FALSE)
 
menuMain = Menu()
menuTerm = Menu()
menuAdvanced = Menu()
menuHelp = Menu()
menuForced = Menu()

menuHelp.add_cascade(label="Open Help with Photos", command=lambda: webbrowser.open('https://iimg.su/s/21/1V1b9oTFMdzwACH1Gkx1uhiZkOK6WPXsnMFkyM6g.png', new=2))
menuHelp.add_cascade(label="Open FAQ (Частые Вопросы)", command=lambda: webbrowser.open('https://faqabout.me/iam/locked'))
menuHelp.add_cascade(label="Show Old Help in Terminal", command=showHelp)
 
menuTerm.add_cascade(label="Режим терминала", command=_terminalChoose) 
menuTerm.add_cascade(label="Консоль разработчика", command=_consoleRun) 

menuForced.add_cascade(label="Зашифровать", command=lambda: useForcfully('lock'))
menuForced.add_cascade(label="Расшифровать", command=lambda: useForcfully('unlock'))

menuAdvanced.add_cascade(label="Использовать принудительно", menu=menuForced)
menuAdvanced.add_separator()
menuAdvanced.add_cascade(label="Использовать старое шифрование до закрытия", command=useOldEncryption)

menuMain.add_cascade(label="Term", menu=menuTerm)
menuMain.add_cascade(label="Advanced", menu=menuAdvanced)
menuMain.add_cascade(label="Help", menu=menuHelp)

root.config(menu=menuMain)
access('set', 'SKEY-STATE', 'off')

if not access('get', 'incorrect_password_attempts'):
    access('set', 'incorrect_password_attempts', '0') 

skeyLabel = Label(root, text='sKey off', fg='pink')
skeyLabel.place(x=117, y=124)
skeyLabel.bind("<Button-1>", lambda e: _skeyEnable()) 

# os.system("""osascript -e 'do shell script "\\" " with administrator privileges'""")

# import subprocess
# root.update()
# app_name = "Python"
# script = f"""
# tell application "System Events"
#     set frontmost of the first process whose name is "{app_name}" to true
# end tell
# """
# subprocess.run(["osascript", "-e", script], check=True)
# general_test()

root.mainloop()
