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


    struct PK
    {
        element_t g_1;
        element_t g_2;
        element_t eggalpha;
    };

    struct MSK
    {
        element_t alpha;
    };

    struct Ciphertext
    {
        LSSS *policy;
        vector<element_s> ct_0;
        vector<element_s> ct_1;
        element_t ct_2;
        element_t ct_3;
        vector<element_s> lambda;
    };

    struct KeyTuple
    {
        struct TK
        {
            string attributes;
            element_t tk_0;
            element_t tk_1;
            unordered_map<string, element_s> tk_2;
        };
        struct SK
        {
            element_t beta;
        };

        TK tk;
        SK sk;
    };

    struct PTC
    {
        element_t ptc_0;
        element_t ptc_1;
    };


    class ABE2OD
    {
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

        void Enc(Ciphertext &cipher, element_t M, LSSS &lsss, pairing_t _pairing);

        void KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing);

        void PDec(PTC &ptc, KeyTuple::TK &tk, Ciphertext &cipher, pairing_t _pairing);

        void TDec(element_t M1, KeyTuple::SK &sk, PTC &ptc, pairing_t _pairing);

        /*
         * DEBUG functions
         */
        void showkeys();

        void showkeytuple(KeyTuple &ktuple);

        void showcipher(Ciphertext &cipher);

        void showPTC(PTC &ptc);

    };

}


#endif //SECRETSHARING_ABE2OD_H
