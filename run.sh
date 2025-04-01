#!/bin/bash
g++ -o cp-abe cp-abe.cpp other/ABE2OD.cpp other/LSSS.cpp other/utilities.cpp -lpbc -lgmp -fopenmp -lcrypto
g++ -o merkle_tree merkle_tree.cpp -fopenmp -lcrypto -lssl
