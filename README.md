RSA Timing attack implementation with Montgomery Product and Powering Ladder
===========================================================================

We implement a timing attack on the RSA algorithm, to recover the private key.
We then implement RSA using Montgomery Powering Ladder as a countermeasure, and show that the timing attack now is ineffective.

Building and running
-------------------

```
$ cd build
$ cmake .. && make
$ ./rsa-server <port> <p> <q> <e>
$ ./attacker <host> <port>
```

example numbers:
```
$ ./rsa-server 31337 97 103 31
$ ./attacker localhost 31337
```

Requires cmake, make, and C++11 compiler support. (tested with Clang)
