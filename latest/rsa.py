import math
import random
import decimal
import os
import hashlib

# RSA MODULE VERSION 1.0 (15 nov 2015)

def check_signature(data, hash, key):
	h = hashlib.sha256()
	encoded = str(data).encode("utf-8")
	h.update(encoded)
	
	message_hashed = h.hexdigest()
	
	if [message_hashed] == decrypt(hash, key):
		return True
	else:
		return False
		
def sign(data, key):
	hash = hashlib.sha256()
	encoded = str(data).encode("utf-8")
	hash.update(encoded)
	return crypt([hash.hexdigest()], key)
	
def crypt(data, key):
	i = 0
	data_send = list(data)
	for v in data:
		if type(v) == str:
			text =[]
			for l in v:
				text.append(pow(int.from_bytes(l.encode("utf-8"), byteorder='big', signed=False), key[0], key[1]))
			data_send[i] = text
			
		else:
			data_send[i] = pow(v, key[0], key[1])
		i += 1
	return data_send

def decrypt(data, key):
	i = 0
	data_send = list(data)
	for v in data:
		if type(v) == list:
			text = ""
			for l in v:
				temp = pow(l, key[0], key[1])
				if temp > 256:
					text += temp.to_bytes(2, "big").decode("utf-8")
				else:
					text += temp.to_bytes(1, "big").decode("utf-8")
			data_send[i] = text
		else:
			data_send[i] = pow(v, key[0], key[1])
		i += 1
	return data_send
	
def pgcd(a,b):
	# On trie les valeurs pour que a >= b
	if a < b:
		a, b = b, a
	
	# Alogithme d'euclide
	# fr.wikipedia.org/wiki/Algorithme_d'Euclide
	r = 1
	while r != 0:
		r = a%b
		if r != 0:
			a = b
			b = r
			
	return b

def isPrime(N):
	divisible = False
	i = 2
	while i <= math.sqrt(decimal.Decimal(N)) and divisible == False:
		if N%i == 0:
			divisible = True
		if i == 2:
			i += 1
		else:
			i += 2
			
	if divisible == True:
		return False
	else:
		return True
		
def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

def getRandomPrimeNumber(a,b):
	rand = random.SystemRandom()
	found = False
	nbr = rand.randint(a,b)
	
	# Test de primalité de Fermat (probabiliste)
	# fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Fermat
	while pow(2,nbr-1,nbr) != 1 or pow(3,nbr-1,nbr) != 1 or pow(5,nbr-1,nbr) != 1 or pow(7,nbr-1,nbr) != 1:
		nbr = rand.randint(a,b)

	return nbr
	
def generateKeyPair(rsaType):
	rand = random.SystemRandom()
	if rsaType == "RSA-2048":
		binaryKeySize = 2048
		decimalKeySize = 617
		warning = False
	elif rsaType == "RSA-1536":
		binaryKeySize = 1536
		decimalKeySize = 463
		warning = False
	elif rsaType == "RSA-1024":
		binaryKeySize = 1024
		decimalKeySize = 309
		warning = False
	elif rsaType == "RSA-896":
		binaryKeySize = 896
		decimalKeySize = 270
		warning = False
	elif rsaType == "RSA-768":
		binaryKeySize = 768
		decimalKeySize = 232
		warning = True
	elif rsaType == "RSA-704":
		binaryKeySize = 704
		decimalKeySize = 212
		warning = True
	elif rsaType == "RSA-576":
		binaryKeySize = 576
		decimalKeySize = 174
		warning = True
		
	if warning == True:
		warnMessage = "Warning : the key size you have chosen ({}) can be easily cracked, don't use it for cryptographic issues.".format(rsaType)
	else:
		warnMessage = ""
	print(warnMessage)
	
	pSize = int(decimalKeySize/2)
	qSize = decimalKeySize-pSize

	p = getRandomPrimeNumber(10**(pSize-1),10**pSize-1)
	q = getRandomPrimeNumber(10**(qSize-1),10**qSize-1)

	n = p*q
	euler = (p-1)*(q-1)
	
	e = rand.randint(2, 25)
	while pgcd(euler, e) != 1:
		e = rand.randint(2, 25)
	
	d = modinv(e, euler)
	
	publicKeyFile = open("public.key", "w")
	publicKeyFile.write("{},{}".format(e,n))
	publicKeyFile.close()
	
	privateKeyFile = open("private.key", "w")
	privateKeyFile.write("{},{}".format(d,n))
	privateKeyFile.close()
	
	# with open('test.txt', 'rb') as f:
		# data = f.read()
		# text = ""
		# for c in data:
			# text += str((c**e)%n)+","
		# text = text[:-1]
			
		# with open('crypted.txt', 'wb') as f:
			# f.write(text.encode('utf-8'))
			
		# with open('crypted.txt', 'rb') as f:
			# letters = f.read().decode().split(",")
			# for letter in letters:
				# print(chr(pow(int(letter), d, n)).encode('utf-8'))
		
	# C = (65**e)%n
	# print("\nCrypted:\n", C)
	
	# M = pow(C, d, n)
	# print("\nDecrypted:\n", M)
	return (e,n), (d,n)
	
	
