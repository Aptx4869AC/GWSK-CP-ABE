#!/bin/bash
g++ -o test test.cpp other/ABE2OD.cpp other/LSSS.cpp other/utilities.cpp -lpbc -lgmp -fopenmp -lcrypto
./test
