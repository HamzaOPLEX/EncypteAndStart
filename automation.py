import argparse
from netmiko import ConnectHandler
import pickle
import yaml
from encryptLogin import get_login  # My Script
import sys
import threading
from getpass import getpass
import os


class automation:
    def login(self):
        with open('Deviceinfo.yaml', 'r') as read:
            ymlfile = yaml.load(read, Loader=yaml.FullLoader)
            devices = list(ymlfile.keys())
            pickled_data = {}
            for device in devices:
                hostname = device
                host = ymlfile[device][0]['Host']
                devices_type = ymlfile[device][1]['Device']
                print(f'Enter Login information of {hostname}:{host}')
                username = input('Enter Username :')
                password = getpass('Enter Password :')
                secret = getpass('Enter secret :')
                login = get_login()
                usr, pwd, scrt = login.encrypt(username, password, secret)
                pickled_data[hostname] = {'username': usr, 'password': pwd,
                                          'secret': scrt, 'device': devices_type,
                                          'host': host}
            with open('autologin.enc', 'wb') as pklwr:
                pickle.dump(pickled_data, pklwr)

    def start(self):
        def start_netmiko_work(host, device_type, username, password, secret, hostname):
            print(f'[!] Waiting SSH Connection to {hostname}:{host}')
            deviceinfo = {'device_type': device_type, 'host': host,
                          'username': username, 'password': password, 'secret': secret}
            ssh_conn = ConnectHandler(**deviceinfo)
            ssh_conn.enable()
            print('[+] SSH Connection Done')
            print(ssh_conn.send_command('sh ip interface brief'))

        try:
            with open('autologin.enc', 'rb') as pklrd:
                loadpickl = pickle.load(pklrd)
                devices = list(loadpickl.keys())
        except Exception as err:
            print(err, '\nplease use -l option to setup your device login information')
        for device in devices:
            # [0] = key
            # [1] = encrypted object

            usernameinfo = loadpickl[device]['username']
            Passwordinfo = loadpickl[device]['password']
            Secretinfo = loadpickl[device]['secret']
            host = loadpickl[device]['host']
            device_type = loadpickl[device]['device']
            login = get_login()
            username = login.decrypt(usernameinfo[0], usernameinfo[1])
            password = login.decrypt(Passwordinfo[0], Passwordinfo[1])
            secret = login.decrypt(Secretinfo[0], Secretinfo[1])

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
