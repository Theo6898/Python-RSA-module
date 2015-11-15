import rsa
import os

# FAKE WORKING EXEMPLE on PYTHON 3
# For security issues, server and user need to know their respective public keys for sure
# You need a trust authoritie to check if the public keys are correct

#Generating key pairs
publicKeyUser, privateKeyUser = rsa.generateKeyPair("RSA-1024")
publicKeyServer, privateKeyServer = rsa.generateKeyPair("RSA-1024")

# user crypt message with server's public key and sign it with its own private key
data = ["GET /index.php", "ssl-version: 1.0"]
data_crypted = rsa.crypt(data, publicKeyServer)
data_signed = rsa.sign(data, privateKeyUser)

# server decrypt the message with its own private key and check if the message has been signed by the user itself
data_decrypted = rsa.decrypt(data_crypted, privateKeyServer)
if rsa.check_signature(data_decrypted, data_signed, publicKeyUser) == True:
	print("Message received :\n", data_decrypted)
else:
	print("Invalid signature, man in the middle attack")

os.system("pause")
