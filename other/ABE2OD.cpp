#include "../include/ABE/ABE2OD.h"

using namespace ABE2ODSPACE;

/**
 *
 * @param pairing
 */
void ABE2OD::Setup(pairing_t pairing)
{
    element_init_G1(pk.g_1, pairing);
    element_init_G2(pk.g_2, pairing);
    element_init_GT(pk.eggalpha, pairing);  //e(g_1,g_2)^a, G1*G2->GT
    element_init_Zr(msk.alpha, pairing);

    // random
    element_t alpha;
    element_init_Zr(alpha, pairing);
    element_random(alpha);

    // public key
    element_random(pk.g_1);
    element_random(pk.g_2);

    pairing_apply(pk.eggalpha, pk.g_1, pk.g_2, pairing);
    element_pow_zn(pk.eggalpha, pk.eggalpha, alpha);

    //secret key
    element_set(msk.alpha, alpha);

    element_clear(alpha);
}

/**
 *
 * @param keytuple
 * @param _attributes
 * @param _pairing
 */
void ABE2OD::KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing)
{
    keytuple.tk.attributes = _attributes;
    vector <string> attributes;
    string2attribute_Set(attributes, _attributes);

    element_init_Zr(keytuple.sk.beta, _pairing);
    element_init_G2(keytuple.tk.tk_0, _pairing);
    element_init_G1(keytuple.tk.tk_1, _pairing);

    // randomness
    element_t r, beta;
    element_init_Zr(r, _pairing);
    element_init_Zr(beta, _pairing);
    element_random(r);
    element_random(beta);

    // decryption key
    element_set(keytuple.sk.beta, beta);

    // transformation key
    element_t left, right, invert_beta;
    element_init_G2(left, _pairing);
    element_init_G2(right, _pairing);
    element_init_Zr(invert_beta, _pairing);
    element_invert(invert_beta, beta);

    // tk_0
    element_pow_zn(left, pk.g_2, msk.alpha);
    element_pow_zn(left, left, invert_beta);
    element_pow_zn(right, pk.g_2, r);
    element_pow_zn(right, right, invert_beta);
    element_mul(keytuple.tk.tk_0, left, right);

    // tk_1
    element_pow_zn(keytuple.tk.tk_1, pk.g_1, r);
    element_pow_zn(keytuple.tk.tk_1, keytuple.tk.tk_1, invert_beta);

    // tk_2
    for (auto e: attributes)
    {
        element_s temp_tk_2;
        element_init_G2(&temp_tk_2, _pairing);
        element_from_hash(&temp_tk_2, (void *) e.c_str(), e.length());
        element_pow_zn(&temp_tk_2, &temp_tk_2, r);
        element_pow_zn(&temp_tk_2, &temp_tk_2, invert_beta);
        keytuple.tk.tk_2.emplace(e, temp_tk_2);
    }

    element_clear(left);
    element_clear(right);
    element_clear(invert_beta);
    element_clear(r);
    element_clear(beta);
}


void ABE2OD::Enc(Ciphertext &cipher, element_t M, LSSS &lsss, pairing_t _pairing)
{

    int lsss_row = lsss.M.size();
    int lsss_col = lsss.M[0].size();
    cipher.policy = &lsss;
    element_init_G1(cipher.ct_2, _pairing);
    element_init_GT(cipher.ct_3, _pairing);

    // 转椭圆曲线上的点
    element_t msg;
    element_init_GT(msg, _pairing);
    element_set(msg, M);
//    element_printf("msg = %B\n", msg);

    // El Gamal layer
    // ct_3
    element_s s;
    element_init_Zr(&s, _pairing);
    element_random(&s);
    element_pow_zn(cipher.ct_3, pk.eggalpha, &s);
    element_mul(cipher.ct_3, cipher.ct_3, msg);

    // C2
    element_pow_zn(cipher.ct_2, pk.g_1, &s);


    // 随机元 v 与 t
    vector <element_s> v;
    v.push_back(s);
    for (int i = 0; i < lsss_col - 1; i++)
    {
        element_s temp_y;
        element_init_Zr(&temp_y, _pairing);
        element_random(&temp_y);
        v.push_back(temp_y);
    }
    vector <element_s> t;
    for (int i = 0; i < lsss_row; i++)
    {
        element_s tmp;
        element_init_Zr(&tmp, _pairing);
        element_random(&tmp);
        t.push_back(tmp);
    }

//    for (int i = 0; i < lsss_col; i++)
//    {
//        element_printf("v[%d] = %B ", i + 1, &v[i]);
//    }
//    cout << '\n';
//    for (int i = 0; i < lsss_row; i++)
//    {
//        element_printf("t[%d] = %B ", i + 1, &t[i]);
//    }
//    cout << '\n';

    // access policy layer
    lsss.generateShares(cipher.lambda, v, _pairing);
    assert(cipher.lambda.size() == lsss.M.size());

    // ct_0 ct_1
    for (int i = 0; i < t.size(); ++i)
    {
        element_s ct_0_i;
        element_s ct_1_i;
        element_init_G1(&ct_0_i, _pairing);
        element_init_G2(&ct_1_i, _pairing);

        // ct_0
        element_pow_zn(&ct_0_i, pk.g_1, &t[i]);

        // ct_1
        element_t left, right;
        element_init_G2(left, _pairing);
        element_init_G2(right, _pairing);
        element_pow_zn(left, pk.g_2, &cipher.lambda[i]);

        element_t hash_label, tinv;
        element_init_G2(hash_label, _pairing);
        element_init_Zr(tinv, _pairing);
        element_from_hash(hash_label, (void *) lsss.rho[i].c_str(), lsss.rho[i].size());
        element_neg(tinv, &t[i]);

        element_pow_zn(right, hash_label, tinv);
        element_mul(&ct_1_i, left, right);

        cipher.ct_0.push_back(ct_0_i);
        cipher.ct_1.push_back(ct_1_i);

        element_clear(left);
        element_clear(right);
        element_clear(hash_label);
        element_clear(tinv);
    }
}


void ABE2OD::PDec(PTC &ptc, KeyTuple::TK &tk, Ciphertext &cipher, pairing_t _pairing)
{

    element_init_GT(ptc.ptc_0, _pairing);
    element_init_GT(ptc.ptc_1, _pairing);

    // C0
    element_set(ptc.ptc_1, cipher.ct_3);

    // e(ct_2, tk_0)
    element_t numerator, denominator;
    element_init_GT(numerator, _pairing);
    element_init_GT(denominator, _pairing);
    pairing_apply(numerator, cipher.ct_2, tk.tk_0, _pairing);
    element_set1(denominator);

    // find vector
    vector <element_s> lambda;
    vector <element_s> ct_0;
    vector <element_s> ct_1;
    vector <element_s> tk_2;
    cipher.policy->getValidSharesExt(lambda, ct_0, ct_1, tk_2,
                                     cipher.lambda, cipher.ct_0, cipher.ct_1, tk.tk_2,
                                     tk.attributes, _pairing);


    vector <element_s> w;
    cipher.policy->findVector(w, tk.attributes, _pairing);

//    for (int i = 0; i < w.size(); i++)
//    {
//        element_printf("omega = %B\n", &w[i]);
//    }


    for (int i = 0; i < w.size(); i++)
    {
        element_t left, right;
        element_init_GT(left, _pairing);
        element_init_GT(right, _pairing);

        // CP1 part
        pairing_apply(left, &ct_1[i], tk.tk_1, _pairing);
        pairing_apply(right, &ct_0[i], &tk_2[i], _pairing);
        element_mul(left, left, right);
        element_pow_zn(left, left, &w[i]);
        element_mul(denominator, denominator, left);

        element_clear(left);
        element_clear(right);
    }


    element_div(ptc.ptc_0, numerator, denominator);

    element_clear(denominator);
    element_clear(numerator);

    for (auto it = ct_0.begin(); it != ct_0.end(); ++it)
    {
        element_clear(&(*it));
    }
    ct_0.clear();
    for (auto it = ct_1.begin(); it != ct_1.end(); ++it)
    {
        element_clear(&(*it));
    }
    ct_1.clear();
    for (auto it = lambda.begin(); it != lambda.end(); ++it)
    {
        element_clear(&(*it));
    }
    lambda.clear();
    for (auto it = tk_2.begin(); it != tk_2.end(); ++it)
    {
        element_clear(&(*it));
    }
    tk_2.clear();
    for (auto it = w.begin(); it != w.end(); ++it)
    {
        element_clear(&(*it));
    }
    w.clear();


}

void ABE2OD::TDec(element_t M1, KeyTuple::SK &sk, PTC &ptc, pairing_t _pairing)
{

    element_t msg, denominator;
    element_init_GT(msg, _pairing);
    element_init_GT(denominator, _pairing);
    element_pow_zn(denominator, ptc.ptc_0, sk.beta);

    element_set(msg, ptc.ptc_1);
    element_div(msg, msg, denominator);
//    element_printf("dec msg = %B\n", msg);


    element_set(M1, msg);

    element_clear(msg);
    element_clear(denominator);
}

ABE2OD::ABE2OD()
{}

ABE2OD::~ABE2OD()
{}

void ABE2OD::showkeys()
{
    element_printf("Public Key:\n g_1 = %B\n g_2 = %B\n e(g_1,g_2)^alpha = %B\n", pk.g_1, pk.g_2, pk.eggalpha);
    element_printf("Master Secret Key:\n alpha = %B\n", msk.alpha);
}

void ABE2OD::showkeytuple(KeyTuple &keytuple)
{
    element_printf("Decryption key sk.beta = %B\n", keytuple.sk.beta);

    element_printf("T1 Transformation key: \ntk_0 = %B\ntk_1 = %B\n", keytuple.tk.tk_0, keytuple.tk.tk_1);
    for (auto e: keytuple.tk.tk_2)
    {
        element_printf("tk_2: %s \t %B\n", e.first.c_str(), &e.second);
    }
}

void ABE2ODSPACE::ABE2OD::showcipher(ABE2ODSPACE::Ciphertext &cipher)
{
    element_printf("ct_2 = %B\n", cipher.ct_2);
    element_printf("ct_3 = %B\n", cipher.ct_3);

    assert(cipher.ct_0.size() == cipher.ct_1.size());
    assert(cipher.ct_0.size() == cipher.lambda.size());

    for (int i = 0; i < cipher.ct_0.size(); i++)
    {
        element_printf("ct_0_%d = %B\n", i, &cipher.ct_0[i]);
        element_printf("ct_1_%d = %B\n", i, &cipher.ct_1[i]);
        element_printf("lambda%d = %B\n", i, &cipher.lambda[i]);
    }
}


void ABE2OD::showPTC(ABE2ODSPACE::PTC &ptc)
{
    element_printf("ptc_0 = %B\n", ptc.ptc_0);
    element_printf("ptc_1 = %B\n", ptc.ptc_1);
}

