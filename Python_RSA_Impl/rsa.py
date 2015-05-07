import math, copy, random

keys = {}
config = {}

def init():
	""" NB! Keys are hardcoded for repeatability
		Public key: (e, n)
		Private key: d
	"""
	p = 72921395523034486567525736371230370633973787029153043254895253767587177948354404505015843041682240089 			# prvate
	q = 27028138044587582353904781804159356623304801440906159575368078211171173680092726609842044176970728203			# private
	e = (1<<16)+1# public
	# p = 97
	# q = 103
	# e = 31
	n = p*q 					# public
	tot_n = (p-1)*(q-1)			
	d = ModInverse(e, tot_n)	#private
	config = {'p': p,
			 'q': q,
			 'tot_n': tot_n,
			 'block_size': 83 }
	keys = {'n': n,
			'e': e,
			'd': d }

	return config, keys

def ModInverse(a, n):
	""" Calculates the modular inverse of a mod n.
		http://www.wikiwand.com/en/Extended_Euclidean_algorithm#/Modular_integers
	"""
	(t, new_t, r, new_r) = 0, 1, int(n), int(a)
	while new_r != 0:
		quotient = r//new_r
		(t, new_t) = (new_t, t - quotient * new_t)
		(r, new_r) = (new_r, r - quotient * new_r)
	if r > 1:
		raise ArithmeticError("ERROR: %d is not invertible modulo %d. \n r was: %d, new_r was %d " % (a, n, r, new_r))
	if t < 0:
		t = t + n
	return t

def MongomeryProduct(a, b, nprime, r, n):
	""" Montgomery product."""
	t = a * b
	m = t * nprime % r
	u = (t + m*n)//r
	return u-n if (u >= n) else u

def nPrime(n):
	""" Calculates r^{-1} and n' as used in Montgomery exponentiation"""
	# n is a k-bit number.
	# r should be 2^k
	k = math.floor(math.log2(int(n))) + 1
	r = int(math.pow(2, k))
	rInverse = ModInverse(r, n)
	nPrime = (r * rInverse -1) // n
	return (r, nPrime)

def num2bits(num):
	bits = []
	k = math.floor(math.log2(num)) + 1
	for i in list(reversed(list(range(0,k)))):
		bits.append(num >> i & 1)
	return bits


def ModExp(M, d, n):
	""" Montgomery binary exponentiation"""
	if n%2 != 1:
		raise ValueError("N must be odd!")
	(r, nprime) = nPrime(n)
	M_bar = (M * r) % n
	x_bar = 1 * r % n
	bit_list = num2bits(d)
	for e_i in bit_list:
		x_bar = MongomeryProduct(x_bar, x_bar, nprime, r, n)
		if e_i == 1:
			x_bar = MongomeryProduct(M_bar, x_bar, nprime, r, n)
	x = MongomeryProduct(x_bar, 1, nprime, r, n)
	return x

def encrypt(message):
	""" Encrypt a message using the public key in getKeys()""" 
	e, n = keys['e'], keys['n']
	number_list = string2num(message)
	blocks = num2blocks(number_list, config['block_size'])
	return [ModExp(block, e, n) for block in blocks]

def decrypt(ciphertext):
	""" Decrypt a ciphertext using the private key in getKeys()"""
	d, n = keys['d'], keys['n']
	blocks = [ModExp(block, d, n) for block in ciphertext]
	number_list = blocks2num(blocks, config['block_size'])
	return num2string(number_list)
	# return ModExp(int(ciphertext), int(d), int(n))


def sign(message):
	return (message, encrypt(message))

"""
Below functions are used for converting between String message and the corresponding 
numbers we work with in RSA
"""
def string2num(strn):
	"""Converts a string to a list of integers based on ASCII values"""
	# Note that ASCII printable characters range is 0x20 - 0x7E
	return [ord(char) for char in strn]

def num2string(l):
	"""Converts a list of integers to a string based on ASCII values"""
	# Note that ASCII printable characters range is 0x20 - 0x7E
	return ''.join(map(chr, filter(lambda c: c!=0,l)))

def num2blocks(l, n):
	"""Take a list of integers(each between 0 and 127), and combines them
	into block size n using base 256. If len(L) % n != 0, use some random
	junk to fill L to make it."""
	# Note that ASCII printable characters range is 0x20 - 0x7E
	returnList = []
	toProcess = copy.copy(l)
	if len(toProcess) % n != 0:
		for i in range(0, n - len(toProcess) % n):
			toProcess.append(0)
	for i in range(0, len(toProcess), n):
		block = 0
		for j in range(0, n):
			block += toProcess[i + j] << (8 * (n - j - 1))
		returnList.append(block)
	return returnList

def blocks2num(blocks, n):
	"""inverse function of num2blocks."""
	toProcess = copy.copy(blocks)
	returnList = []
	for numBlock in toProcess:
		inner = []
		for i in range(0, n):
			inner.append(numBlock % 256)
			numBlock >>= 8
		inner.reverse()
		returnList.extend(inner)
	return returnList

config, keys = init()


if __name__ == '__main__':
	"""
	Example.
	This will not run if the module is imported.
	"""
	print("P: ",config['p'])
	print("Q: ",config['q'])
	print("n: ",keys['n'])
	print("e: ",keys['e'])
	print("d: ",keys['d'])

	""" This seems to be close to the largest integer we can encrypt/decrypt properly.
		Not sure why.
	"""
	M = """
        Bacon ipsum dolor amet ham hock tri-tip hamburger tail boudin pork rump strip steak. 
        Capicola hamburger pork salami ball tip t-bone, cow pig tri-tip chuck kielbasa 
        sirloin alcatra. Pastrami ball tip tenderloin ground round, pork belly meatball 
        swine pork salami pork chop landjaeger sirloin ribeye ham chuck. 
        Brisket prosciutto kielbasa filet mignon hamburger spare ribs porchetta.
    """
	C = encrypt(M)
	S = decrypt(C)
	print("Message: ", M)
	print ("Ciphertext: ",C)
	print ("Decrypted: ", S)
