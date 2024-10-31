#ifndef SECRETSHARING_ABE2OD_H
#define SECRETSHARING_ABE2OD_H

#include <vector>
#include <unordered_map>
#include <bitset>
#include <string>
#include <openssl/sha.h>
#include "../pbc/pbc.h"
#include "../PicoSHA2/picosha2.h"

#include "utilities.h"
#include "LSSS.h"

using namespace std;


namespace ABE2ODSPACE
{
	

    struct PK {
        element_t g;
        element_t eggalpha;
        element_t ga;
    };

    struct MSK {
        element_t galpha;
    };
    
    struct Ciphertext {
        LSSS *policy;
        element_t C0;
        string C1;//hash
        element_t C2;
        vector<element_s> Di;
        vector<element_s> Ei;
        vector<element_s> lambda;
    };
    
    struct KeyTuple {
        struct TK {
            string attributes;
            element_t K;
            element_t L;
            unordered_map<string, element_s> Ky; 
        };
        struct HK {
            element_t gamma_1;
            element_t gamma_2;
        };
        struct DK {
            element_t beta;
        };

        TK tk_1;
        TK tk_2;
        HK hk;
        DK dk;
    };
    
    struct PTC {
        element_t C0;
        string C1;
        element_t CP1;
        element_t CP2;
    };
    
    struct TC {
        element_t T0;
        string T1;
        element_t T2;
    };
    


    class ABE2OD {
    public:
        PK pk;
        MSK msk;

        // constructor and destructor
        ABE2OD();
        ~ABE2OD();

        /*
         *
         */
        void Setup(pairing_t _pairing);
        void Enc(Ciphertext &cipher, string M, LSSS &lsss, pairing_t _pairing);
        void KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing);
        void Transform1(PTC &ptc, KeyTuple::TK &tk_1, KeyTuple::TK &tk_2, Ciphertext &cipher, pairing_t _pairing);
        void Transform2(TC &tc, KeyTuple::HK &hk, PTC &ptc, pairing_t _pairing);
        string Dec(KeyTuple::DK &dk, TC &tc, pairing_t _pairing);

        /*
         * DEBUG functions
         */
        void showkeys();
        void showkeytuple(KeyTuple &ktuple);
        void showcipher(Ciphertext &cipher);
        void showPTC(PTC &ptc);
        void showTC(TC &tc);

    };

}


#endif //SECRETSHARING_ABE2OD_H
