import rsa
import os

#---------------------------------------------------------------------------------
# Generating key pairs
#---------------------------------------------------------------------------------
publicKey, privateKey = rsa.generateKeyPair("RSA-1024")

# generateKeyPair function returns 2 tuples :
	# - the public key : (e,n)
	# - the private key : (d,n)
	
# generateKeyPair takes 1 argument, a string that is a RSA-NUMBER (key size)
# RSA numbers below RSA-1024 are not secured enough,
# use them for better performances during developement
	# - "RSA-2048"
	# - "RSA-1536"
	# - "RSA-1024"
	# - "RSA-896"
	# - "RSA-768"
	# - "RSA-704"
	# - "RSA-576"


#---------------------------------------------------------------------------------
# Crypt a message
#---------------------------------------------------------------------------------
data = ["abc", 1, 7]
data_crypted = rsa.crypt(data, key)

# it takes 2 arguments :
# - a LIST of datas to encrypt (it can only contain int and str)
# - a key (public or private), the message can be decrypted with the opposite key
# exemple : by encrypting a message with a public key you will be able to decrypt
# it with the corresponding private key and vice-versa.

# the function return a list of the encrypted datas
# in this case it could return something like that
# [[89, 23, 41], 31, 97]
# as you can see every single letter in the 'data' string 'abc' is transformed by a number


#---------------------------------------------------------------------------------
# Decrypt a message
#---------------------------------------------------------------------------------
data_crypted = [[89, 23, 41], 31, 97]
data_clear = rsa.decrypt(data_crypted, key)

# it takes 2 arguments :
# - a LIST of encrypted datas given by the crypt() function
# - a key (public or private) depending on wich key has been used to crypt the message

# the function return the original list of datas.

os.system("pause")
