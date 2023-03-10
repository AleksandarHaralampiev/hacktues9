from cryptography.fernet import Fernet

key = Fernet.generate_key()

crypter = Fernet(key)

strg = "mypassword"

pw = crypter.encrypt(strg.encode())

print(pw)

decryptString = crypter.decrypt(pw)

print(decryptString.decode())
