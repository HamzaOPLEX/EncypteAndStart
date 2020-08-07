from netmiko import ConnectHandler # ConnectHandler for using ssh connection
from encryptLogin import get_login  # i creat this module for encrypt login 
from getpass import getpass # get password without display it on screen
import threading    # for using multithreading
import argparse     # command line parser
import pickle
import yaml
import sys
import os


class automation:
    def login(self):
        # Opening Deviceinfo.yaml as read
        try:
            with open('Deviceinfo.yaml') as read:
                #after read the file we need to conver yaml syntax to a dictionary sysntax
                ymlfile = (yaml.load(read, Loader=yaml.FullLoader))
                devices = list(ymlfile.keys()) # get all hostnames and save them in a list 
                pickled_data = {} # here we will put our pickle Data
                for device in devices: # loop into hostnames
                    host = ymlfile[device][0]['Host']
                    devices_type = ymlfile[device][1]['Device']
                    print(f'Enter Login information of {device}:{host}')
                    username,password,secret = get_login.getCiscoLogin() # use my module to enter login info
                    usr, pwd, scrt = get_login.encrypt(username, password, secret) # encrypt login info
                    pickled_data[device] = {'username': usr, 'password': pwd,'secret': scrt, 'device': devices_type,'host': host}
                with open('autologin.enc', 'wb') as pklwr: # save encrypted data in a file 
                    pickle.dump(pickled_data, pklwr)
        except Exception as err :
            ouputerr = str(err).replace('[Errno 2]','[!] FileNotFoundErr : ')
            print(ouputerr)
            
    def start(self):
        
                # start_netmiko_work this function for creat all Device Config
        def start_netmiko_work(host, device_type, username, password, secret, hostname):

            print(f'[!] Waiting SSH Connection to {hostname}:{host}')
            deviceinfo = {'device_type': device_type, 'host': host,'username': username, 'password': password, 'secret': secret}
            try : 
                ssh_conn = ConnectHandler(**deviceinfo).enable()
                print(f'[+] You Are Now Connected to {hostname}:{host} Via SSH')
            except Exception as Err : 
                print(f'[!] Failed SSH Connection to {hostname}:{host}')
                print(Err)

        
        try:
            with open('autologin.enc', 'rb') as pklrd:
                loadpickl = pickle.load(pklrd)
                devices = list(loadpickl.keys())
        except FileNotFoundError as err:
            print(err, '\nplease use -l option to setup your device login information')
            sys.exit
        for device in devices:
            # [0] = key
            # [1] = encrypted object

            usernameinfo = loadpickl[device]['username']
            Passwordinfo = loadpickl[device]['password']
            Secretinfo = loadpickl[device]['secret']
            host = loadpickl[device]['host']
            device_type = loadpickl[device]['device']
            encryptedinfo = (usernameinfo,Passwordinfo,Secretinfo)
            username,password,secret = get_login.decrypt(encryptedinfo)
            print(username,password,secret)
            thread = threading.Thread(target=start_netmiko_work, args=(
                host, device_type, username, password, secret, device))
            thread.start()
            thread.join()


if len(sys.argv) > 1 and len(sys.argv) <= 2:

    my_parser = argparse.ArgumentParser(
        prog='automation.py', usage='%(prog)s [-s] or [-l]\n!use just one option!', description='automate network stuff', epilog='Enjoy the program! :)')
    my_parser.version = '1.0'
    my_parser.add_argument('-l', '--login', metavar="login", help='prompt for enter login info for each device in Deviceinfo.yaml',
                           action='store_const', const=True)

    my_parser.add_argument('-s', '--start', metavar="start", help='start the automation',
                           action='store_const', const=True)

    args = my_parser.parse_args()

    automate = automation()

    if args.login == True:
        automate.login()
    if args.start == True:
        automate.start()


else:
    print("Use -h for see Help")

