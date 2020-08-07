from cryptography.fernet import Fernet
from getpass import getpass

class get_login:
    @staticmethod
    def encrypt(username, password, secret):

        def dothework(login_type, login_info):
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            Crypted_Login = cipher_suite.encrypt(login_info.encode())
            Secure_data[login_type][0] = key
            Secure_data[login_type][1] = Crypted_Login
        LOGIN = ['username', 'password', 'secret']

        Secure_data = {'username': ['', ''],
                       'password': ['', ''], 'secret': ['', '']}

        username_encypted = Secure_data["username"]
        password_encypted = Secure_data["password"]
        secret_encypted = Secure_data["secret"]

        for i in LOGIN:
            if i == 'username':
                dothework('username', username)
            elif i == 'password':
                dothework('password', password)
            elif i == 'secret':
                dothework('secret', secret)

        return (username_encypted, password_encypted, secret_encypted)
    @staticmethod
    def decrypt(encryptedinfo):

        plaintextlogin_info = []

        for encObj in encryptedinfo : 
            info_key = encObj[0]
            info_data = encObj[1]
            cipher_suite = Fernet(info_key)
            plaintext = cipher_suite.decrypt(info_data).decode()
            plaintextlogin_info.append(plaintext)
        return plaintextlogin_info[0],plaintextlogin_info[1],plaintextlogin_info[2]

    
    def getCiscoLogin():
        username = input('Enter Username :')
        password = getpass('Enter Password :')
        secret = getpass('Enter secret :')
        return username,password,secret

if __name__ == '__main__':
    Username = input('Enter Username :')
    Password = getpass('Enter Password :')
    Secret = getpass('Enter Secret :')
    login = get_login()
    u, p, s = login.encrypt(Username, Password, Secret)
    encryptedinfo = (u,p,s)
    u, p, s = login.decrypt(encryptedinfo)
    print(u,p,s)
