from math import log, ceil
from random import randint
import sys

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
	return (g, x -(b//a) * y, y)



def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception("mod inverse does not exist")
	else:
		return x % m


def ext_euclid2(r, n):
	r_ = modinv(r, n)
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

def rsa(m, d, n, nn, r):
	mm = (m*r)%n
	cc = (1*r)%n
	k = len(d)
	sub_count = 0
	for i in range(0, k):
		sub = False
		cc, tmp = MonPro(cc,cc, n, nn, r)
		if d[i]=='1':
			cc, sub = MonPro(mm, cc, n, nn, r)
			#print sub
		sub_count += int(sub)
	c, tmp = MonPro(cc, 1, n, nn, r)
	return c, sub_count


def rsa_sim(m, d, n, nn, r, j):
	mm = (m*r)%n
	cc = (1*r)%n
	
	k = len(d)

	dd = d[:j]
	dd += '1'
	k = len(dd)
	#print "dd=",dd
	sub = False
	for i in range(0, k):
		cc, tmp = MonPro(cc,cc, n, nn, r)
		#sub = True
		if dd[i]=='1':
			cc, sub = MonPro(mm, cc, n, nn, r)
			#print sub
	c, tmp = MonPro(cc, 1, n, nn, r)
	return c, sub

def get_r(n):
	return int(pow(2, ceil(log(n,2))))

def get_message_groups(d, n, nn, r, j):
	size = 5000
	mlist = [randint(10000, 10000000) for i in xrange(size)]
	m_true = []
	m_false = []
	for m in mlist:
		c, bucket = rsa_sim(m, d, n, nn, r, j)
		if bucket:
			m_true.append(m)
		else:
			m_false.append(m)
	return (m_true, m_false)





def attack(dd, n):
	r = get_r(n)
	(rr, nn) = ext_euclid2(r, n)
	d = bin(dd)[2:]
	print "binary d=",d
	k = len(d)
	# Assume First bit of key is 1
	newkey = '1'
	for j in range(1, k):
		# For each bit in d, get two message sets
		(m_true, m_false) = get_message_groups(newkey, n, nn, r, j)
		if len(m_true)==0 or len(m_false)==0:
			(m_true, m_false) = get_message_groups(newkey, n, nn, r,j)
		# Count total number of subtractions for each set (simulates time)
		true_sub_count = false_sub_count = 0
		for m in m_true:
			(c, t_count) = rsa(m, d, n, nn, r)
			true_sub_count += t_count
		for m in m_false:
			(c, f_count) = rsa(m, d, n, nn, r)
			false_sub_count += f_count
		# Take average number of subtractions per message in two groups
		tavg = round(true_sub_count/(1.0*len(m_true)), 6)
		favg = round(false_sub_count/(1.0*len(m_false)), 6)
		# If difference is high, guess the bit as 1, else guess it as 0
	
		print "j=",j,"\td[j]=",d[j],"\tDiff=",abs(tavg-favg),"\tTavg:",tavg,"\tFavg:",favg

		if abs(tavg-favg)>1.0:
			newkey += '1'
		else:
			newkey += '0'
		print "Original key:\t", d

		print "Guessed key:\t", newkey
		if d==newkey:
			print "Guessed Correctly!"
		else:
			print "Attack failed. Try again."

if __name__ == "__main__":
	d = 85
	n = 391
	#d =161521746670640296426473658228859984306663144318152681524054709078245736590366297248377298082656939330673286493230336261991466938596691073112968626710792148904239628873374506302653492009810626437582587089465395941375496004739918498276676334238241465498030036586063929902368192004233L
	#n =161521746670640296426473658228859984306663144318152681524054709078245736590366297248377298082656939330673286493230336261991466938596691073112968626710792148904239628873374506302653492009810626437582587089465395941375496004739918498276676334238241465498030036586063929902368192004233172032080188726965600617167L
	#d = 321474812
	#n = 2147483647
	#d = 219924798127249
	d = 85
	d = 45479
	#d = 235714334261836
	n = 2305842913650672281
	print "d=\t", d
	print "n=\t", n
	if len(sys.argv)>2:
		d = int(sys.argv[1])
		n = int(sys.argv[2])


	attack(d, n)