#!/bin/bash
g++ -o BASA BASA.cpp  -lpbc -lgmp -fopenmp -lcrypto
g++ -o IRBA IRBA.cpp  -lpbc -lgmp -fopenmp -lcrypto
g++ -o IRBA_v2 IRBA_v2.cpp  -lpbc -lgmp -fopenmp -lcrypto

