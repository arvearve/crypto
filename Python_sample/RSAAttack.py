import csv
from math import log, ceil
from random import randint
import sys

data = []
with open('data.csv', 'rb') as f:
    reader = csv.reader(f)
    data = list(reader)


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

def ext_euclid2(r, n):
	r_ = ModInverse(r, n)
	if r_<0:
		r_ += n
	n_ = (1-r*r_)/n
	return (r_, (-1)*n_)


def eea(a, b):
	g0, g1, u0, u1, v0, v1 = a, b, 1, 0, 0, 1
	while g1!=0:
		q = g0/g1
		g0, g1 = g1, g0-g1*q
		u0, u1 = u1, u0-u1*q
		v0, v1 = v1, v0-v1*q
	return (u0, v0)


def MonPro(a_, b_, n, nn, r):
	t = a_*b_
	#t = (a*r%n)*(b*r%n)
	m = (t*nn)%r
	#u = (t+m*n)>>int(log(r,2))
	u = (t+m*n)/r
	#print "u =", u, "n=", n
	if u >= n:
		return (u-n,True)
	else:
		return (u, False)

def MongomeryProduct(a, b,n,nprime,r):
	""" Montgomery product."""
	t = a * b
	m = t * nprime % r
	u = (t + m*n)/r
	return (u-n,True) if (u >= n) else (u,False)

def rsa(m, d, n, nn, r):
	mm = (m*r)%n
	x_bar = (1*r)%n
	k = len(d)
	sub_count = 0
	for i in range(0, k):
		sub = False
		x_bar, tmp = MongomeryProduct(x_bar,x_bar, n, nn, r)
		if d[i]=='1':
			x_bar, sub = MongomeryProduct(mm, x_bar, n, nn, r)

		sub_count += int(sub)
	x, tmp = MongomeryProduct(x_bar, 1, n, nn, r)
	return x, sub_count


def rsa_sim(m, d, n, nn, r, j):
	mm = (m*r)%n
	x_bar = (1*r)%n
	
	k = len(d)

	dd = d[:j]
	dd += '1'

	k = len(dd)

	sub = False
	for i in range(0, k):
		x_bar, tmp = MongomeryProduct(x_bar,x_bar, n, nn, r)
		#sub = True
		if dd[i]=='1':
			x_bar, sub = MongomeryProduct(mm, x_bar, n, nn, r)
			#print sub
	x, tmp = MongomeryProduct(x_bar, 1, n, nn, r)
	return x, sub

def get_r(n):
	return int(pow(2, ceil(log(n,2))))

def message_sets(d, n, nn, r, j,data):
	mlist = data
	m_true = []
	m_false = []
	for m in mlist:
		c, bucket = rsa_sim(int(m[0]), d, n, nn, r, j)
		if bucket:
			m_true.append(m)
		else:
			m_false.append(m)
	return (m_true, m_false)


def RSAAttack(dd, n,data):
	r = get_r(n)
	(rr, nn) = ext_euclid2(r, n)
	d = bin(dd)[2:]
	print "binary d=",d
	#k = len(d)
	# Assume First bit of key is 1
	newkey = '1'
	j = 1
	finished = False
	while(not finished):


		# For each bit in d, get two message sets
		(m_true, m_false) = message_sets(newkey, n, nn, r, j,data)


		if len(m_true)==0 or len(m_false)==0:
			(m_true, m_false) = message_sets(newkey, n, nn, r,j)



		# Count total number of subtractions for each set (simulates time)
		true_sub_count = false_sub_count = 0
		for m in m_true:
			true_sub_count += int(m[2])

		for m in m_false:
			false_sub_count += int(m[2])

		# Take average number of subtractions per message in two groups
		tavg = round(true_sub_count/(1.0*len(m_true)), 6)
		favg = round(false_sub_count/(1.0*len(m_false)), 6)
		# If difference is high, guess the bit as 1, else guess it as 0
		
		#print "j=",j,"\tDiff=",abs(tavg-favg),"\tTavg:",tavg,"\tFavg:",favg
		print "Ratio:",tavg/favg


		# With sleep - 1.08
		#
		if abs(tavg/favg)>1.08:
			newkey += '1'
		else:
			newkey += '0'
		print "Original key:\t", d

		print "Guessed key:\t", newkey

		testMessage = int(data[0][0])

		signMessage,c = rsa(testMessage,str(newkey),n,nn,r)

		if signMessage==int(data[0][1]):
			print "Guessed Correctly!"
			finished = True
		else:
			print "Attack failed. Try again."

		j+=1
if __name__ == "__main__":

	d = 2527
	#d = 235714334261836
	n = 2305842913650672281
	n = 97*103
	print "d=\t", d
	print "n=\t", n
	


RSAAttack(d, n,data)


