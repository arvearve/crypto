RSA Timing attack implementation
================================

We implement a timing attack on the RSA algorithm, to recover the private key.
We then implement RSA using Montgomery Powering Ladder as a countermeasure, and show that the timing attack now is ineffective.

Building and running
-------------------

To create and sign a number of messages, build and run the C program:
```
# Requires cmake, make, and C++11 compiler support.
$ cd build
$ cmake .. && make
$ ./csv <p> <q> <e> <number of messages> # for example 97 103 31 10000

```

After a while you will see a file called data.csv in the same folder. 

To run the attack, copy this into `Attack/output/some_folder`, and run 

```
$ python RSAAttack.py output/<some_folder> <duration to split on>
# for example output/2ms_sleep_33bit_key 4307361
```

This runs the attack on the dataset you generated, with `duration` as the difference in average time between each set used decide whether a bit is 0 or 1. A good approach is to set `duration` to 0 initially, and then stop the script after a few iterations. Look at the script output for a suitable difference to try and split on.

The script saves the sets it generates on each bit as `0000x.dat`. These can be used to plot the data for visualizations.

We have prepared an R script called `rplot.r` in the folder Attack/output. this can be run with the following command:

```
$ Rscript rplot.r <some_folder>  # for example 2ms_sleep_33bit_key
```

this will make a number of plots corresponding to each bit in the key, inside the folder you provided. 