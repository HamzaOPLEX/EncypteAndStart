from cryptography.fernet import Fernet
from getpass import getpass


class get_login:
    def encrypt(self, username=str, password=str, secret=str):

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

    def decrypt(self, key, encryptedobj):
        cipher_suite = Fernet(key)
        plaintext = cipher_suite.decrypt(encryptedobj)
        return plaintext.decode()


if __name__ == '__main__':
    Username = getpass('Enter Username :')
    Password = getpass('Enter Password :')
    Secret = getpass('Enter Secret :')
    login = get_login()
    u, p, s = login.encrypt(Username, Password, Secret)
    a = login.decrypt(u[0], u[1])
    print(a)
