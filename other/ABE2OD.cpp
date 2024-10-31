//
// Created by Xiaoguo on 2022/7/27.
//
#include "../include/ABE/ABE2OD.h"

using namespace ABE2ODSPACE;

string xorHashes(const std::string &hash1, const std::string &hash2)
{
    // 确保两个哈希具有相同的位数
    size_t bitLength = std::max(hash1.size(), hash2.size());
    std::string paddedHash1 = hash1;
    std::string paddedHash2 = hash2;
    if (hash1.size() < bitLength)
    {
        paddedHash1.insert(0, bitLength - hash1.size(), '0');
    }
    if (hash2.size() < bitLength)
    {
        paddedHash2.insert(0, bitLength - hash2.size(), '0');
    }

    // 对两个哈希进行异或操作
    bitset<256> bitset1(paddedHash1);
    bitset<256> bitset2(paddedHash2);
    bitset<256> result = bitset1 ^ bitset2;
    string resultString = result.to_string();

    //剔除result字符串前缀中的连续0
    size_t firstNonZero = resultString.find_first_not_of('0');
    if (firstNonZero != string::npos)
    {
        resultString = resultString.substr(firstNonZero);
    } else
    {
        resultString = "0";
    }
    //cout<<resultString<<'\n';
    // 将结果转换为字符串
    return resultString;
}


string elementToHash(element_t &element)
{
    // 获取元素R的字节表示
    size_t byteLength = element_length_in_bytes(element);
    unsigned char *bytes = new unsigned char[byteLength];
    element_to_bytes(bytes, element);

    // 使用SHA-256进行哈希计算
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes, byteLength, hash);

    // 将哈希值转换为01字符串
    std::string hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            hashString += ((hash[i] >> j) & 1) ? '1' : '0';
        }
    }

    delete[] bytes;

    return hashString;
}


void ABE2OD::Setup(pairing_t pairing)
{
    element_init_G1(pk.g, pairing);//g
    element_init_G1(pk.ga, pairing);//g^a
    element_init_GT(pk.eggalpha, pairing);//e(g,g)^a, G1*G1->GT
    element_init_G1(msk.galpha, pairing);//msk g^a

    // randomness
    element_t a, alpha;
    element_init_Zr(a, pairing);
    element_init_Zr(alpha, pairing);
    element_random(a);
    element_random(alpha);
    element_set_str(alpha, "231", 10);
    element_set_str(a, "567", 10);
    element_printf("alpha = %B\n", alpha);
    element_printf("a = %B\n", a);

    // public key
    element_random(pk.g);
    element_pow_zn(pk.ga, pk.g, a);

    pairing_apply(pk.eggalpha, pk.g, pk.g, pairing);
    element_pow_zn(pk.eggalpha, pk.eggalpha, alpha);

    //secret key
    element_pow_zn(msk.galpha, pk.g, alpha);

    element_clear(a);
    element_clear(alpha);
}


void ABE2OD::Enc(Ciphertext &cipher, string M, LSSS &lsss, pairing_t _pairing)
{

    int lsss_row = lsss.M.size();
    int lsss_col = lsss.M[0].size();
    cipher.policy = &lsss;
    element_init_GT(cipher.C0, _pairing);
    element_init_G1(cipher.C2, _pairing);

    //生成随机元
    element_t R;
    element_init_GT(R, _pairing);
    element_random(R);
    element_printf("R = %B\n", R);

    // El Gamal layer
    // C1
    string hash_R = elementToHash(R);
    cout << "hash_R = " << hash_R << '\n';
    string xorResult = xorHashes(hash_R, M);
    cipher.C1 = xorResult;

    // C0
    element_s s;
    element_init_Zr(&s, _pairing);
    element_from_hash(&s, (void *) (hash_R + M).c_str(), (hash_R + M).length());
    element_printf("s = %B\n", &s);
    element_pow_zn(cipher.C0, pk.eggalpha, &s);
    //element_printf("e(g,g)^αs = %B\n", cipher.C0);
    element_mul(cipher.C0, cipher.C0, R);
    //element_printf("R* e(g,g)^αs = %B\n", cipher.C0);

    // C2
    element_pow_zn(cipher.C2, pk.g, &s);


    // 随机元 v 与 r    
    vector <element_s> v;
    v.push_back(s);
    for (int i = 0; i < lsss_col - 1; i++)
    {
        element_s temp_y;
        element_init_Zr(&temp_y, _pairing);
        element_set_si(&temp_y, (i + 1) * 2);
        v.push_back(temp_y);
    }
    vector <element_s> r;
    for (int i = 0; i < lsss_row; i++)
    {
        element_s tmp;
        element_init_Zr(&tmp, _pairing);
        element_set_si(&tmp, (i + 1) * 3);
        r.push_back(tmp);
    }

    for (int i = 0; i < lsss_col; i++)
    {
        element_printf("v[%d] = %B ", i + 1, &v[i]);
    }
    cout << '\n';
    for (int i = 0; i < lsss_row; i++)
    {
        element_printf("r[%d] = %B ", i + 1, &r[i]);
    }
    cout << '\n';

    // access policy layer
    // vector<element_s> lambda;
    lsss.generateShares(cipher.lambda, v, _pairing);
    assert(cipher.lambda.size() == lsss.M.size());

    // Di Ei
    for (int i = 0; i < r.size(); ++i)
    {
        element_s di;
        element_s ei;
        element_init_G1(&di, _pairing);
        element_init_G1(&ei, _pairing);

        // di
        element_pow_zn(&di, pk.g, &r[i]);

        // ei
        element_pow_zn(&ei, pk.ga, &cipher.lambda[i]);
        element_t hashlabel, rinv;
        element_init_G1(hashlabel, _pairing);
        element_init_Zr(rinv, _pairing);
        element_from_hash(hashlabel, (void *) lsss.rho[i].c_str(), lsss.rho[i].size());
        //element_printf("hashlabel = %B\n", hashlabel);
        element_neg(rinv, &r[i]);
        element_pow_zn(hashlabel, hashlabel, rinv);
        element_mul(&ei, &ei, hashlabel);

        cipher.Di.push_back(di);
        cipher.Ei.push_back(ei);

        element_clear(hashlabel);
        element_clear(rinv);
    }
}


void ABE2OD::KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing)
{
    keytuple.tk_1.attributes = _attributes;
    keytuple.tk_2.attributes = _attributes;
    vector <string> attributes;
    string2attribute_Set(attributes, _attributes);

    element_init_Zr(keytuple.dk.beta, _pairing);
    element_init_Zr(keytuple.hk.gamma_1, _pairing);
    element_init_Zr(keytuple.hk.gamma_2, _pairing);
    element_init_G1(keytuple.tk_1.K, _pairing);
    element_init_G1(keytuple.tk_1.L, _pairing);
    element_init_G1(keytuple.tk_2.K, _pairing);
    element_init_G1(keytuple.tk_2.L, _pairing);

    // randomness
    element_t t1, t2;
    element_init_Zr(t1, _pairing);
    element_init_Zr(t2, _pairing);
    element_set_si(t1, 4869);
    element_set_si(t2, 1412);

    // decryption key
    element_set_si(keytuple.dk.beta, 73);

    // revocation key
    element_set_si(keytuple.hk.gamma_1, 126066);
    element_set_si(keytuple.hk.gamma_2, 251563);


    // tk_1 transformation key
    element_t betagammainv_1;
    element_init_Zr(betagammainv_1, _pairing);
    element_mul(betagammainv_1, keytuple.dk.beta, keytuple.hk.gamma_1);
    element_invert(betagammainv_1, betagammainv_1);
    element_pow_zn(keytuple.tk_1.K, msk.galpha, betagammainv_1);

    element_t temp_k_1;
    element_init_G1(temp_k_1, _pairing);
    element_mul(betagammainv_1, betagammainv_1, t1);
    element_pow_zn(temp_k_1, pk.ga, betagammainv_1);
    element_mul(keytuple.tk_1.K, keytuple.tk_1.K, temp_k_1);  // t1_K
    element_pow_zn(keytuple.tk_1.L, pk.g, betagammainv_1);  // t1_L



    // tk_2 transformation key
    element_t betagammainv_2;
    element_init_Zr(betagammainv_2, _pairing);
    element_mul(betagammainv_2, keytuple.dk.beta, keytuple.hk.gamma_2);
    element_invert(betagammainv_2, betagammainv_2);
    element_pow_zn(keytuple.tk_2.K, msk.galpha, betagammainv_2);

    element_t temp_k_2;
    element_init_G1(temp_k_2, _pairing);
    element_mul(betagammainv_2, betagammainv_2, t2);
    element_pow_zn(temp_k_2, pk.ga, betagammainv_2);
    element_mul(keytuple.tk_2.K, keytuple.tk_2.K, temp_k_2);  // t2_K
    element_pow_zn(keytuple.tk_2.L, pk.g, betagammainv_2);  // t2_L

    //t2_ky
    for (auto e: attributes)
    {
        element_s temp_ky_1, temp_ky_2;
        element_init_G1(&temp_ky_1, _pairing);
        element_init_G1(&temp_ky_2, _pairing);
        element_from_hash(&temp_ky_1, (void *) e.c_str(), e.length());
        element_from_hash(&temp_ky_2, (void *) e.c_str(), e.length());

        element_pow_zn(&temp_ky_1, &temp_ky_1, betagammainv_1);
        element_pow_zn(&temp_ky_2, &temp_ky_2, betagammainv_2);
        keytuple.tk_1.Ky.emplace(e, temp_ky_1);
        keytuple.tk_2.Ky.emplace(e, temp_ky_2);
    }

    element_clear(t1);
    element_clear(t2);
    element_clear(temp_k_1);
    element_clear(temp_k_2);
    element_clear(betagammainv_1);
    element_clear(betagammainv_2);
}


void ABE2OD::Transform1(PTC &ptc, KeyTuple::TK &tk_1, KeyTuple::TK &tk_2, Ciphertext &cipher, pairing_t _pairing)
{

    element_init_GT(ptc.C0, _pairing);
    element_init_GT(ptc.CP1, _pairing);
    element_init_GT(ptc.CP2, _pairing);

    // C0
    element_set(ptc.C0, cipher.C0);

    // C1
    ptc.C1 = cipher.C1;


    //e(C2, tk_1.K)
    element_t numerator_1, denominator_1;
    element_init_GT(numerator_1, _pairing);
    element_init_GT(denominator_1, _pairing);
    pairing_apply(numerator_1, cipher.C2, tk_1.K, _pairing);  // numerator = e(C2, tk_1.K)

    //e(C2, tk_2.K)
    element_t numerator_2, denominator_2;
    element_init_GT(numerator_2, _pairing);
    element_init_GT(denominator_2, _pairing);
    pairing_apply(numerator_2, cipher.C2, tk_2.K, _pairing);  // numerator = e(C2, tk_2.K)


    // find vector
    vector <element_s> lambda;
    vector <element_s> Ei;
    vector <element_s> Di;
    vector <element_s> ky_1;
    vector <element_s> ky_2;
    cipher.policy->getValidSharesExt(lambda, Ei, Di, ky_1,
                                     cipher.lambda, cipher.Ei, cipher.Di, tk_1.Ky,
                                     tk_1.attributes, _pairing);

    cipher.policy->getValidSharesExt(lambda, Ei, Di, ky_2,
                                     cipher.lambda, cipher.Ei, cipher.Di, tk_2.Ky,
                                     tk_2.attributes, _pairing);


    vector <element_s> ws_1;
    vector <element_s> ws_2;
    cipher.policy->findVector(ws_1, tk_1.attributes, _pairing);
    cipher.policy->findVector(ws_2, tk_2.attributes, _pairing);


    for (int i = 0; i < ws_1.size(); i++)
    {
        element_printf("omega = %B\n", &ws_1[i]);
    }

    element_set1(denominator_1);
    element_set1(denominator_2);
    for (int i = 0; i < ws_1.size(); i++)
    {
        element_t left_1, right_1, left_2, right_2;
        element_init_GT(left_1, _pairing);
        element_init_GT(right_1, _pairing);
        element_init_GT(left_2, _pairing);
        element_init_GT(right_2, _pairing);


        // CP1 part
        pairing_apply(left_1, &Ei[i], tk_1.L, _pairing);
        pairing_apply(right_1, &Di[i], &ky_1[i], _pairing);
        element_mul(left_1, left_1, right_1);
        element_pow_zn(left_1, left_1, &ws_1[i]);
        element_mul(denominator_1, denominator_1, left_1);

        // CP2 part
        pairing_apply(left_2, &Ei[i], tk_2.L, _pairing);
        pairing_apply(right_2, &Di[i], &ky_2[i], _pairing);
        element_mul(left_2, left_2, right_2);
        element_pow_zn(left_2, left_2, &ws_2[i]);
        element_mul(denominator_2, denominator_2, left_2);


        element_clear(left_1);
        element_clear(right_1);
        element_clear(left_2);
        element_clear(right_2);
    }


    element_div(ptc.CP1, numerator_1, denominator_1);
    element_div(ptc.CP2, numerator_2, denominator_2);
    //element_printf("ptc.CP1 = %B\n", ptc.CP1);
    //element_printf("ptc.CP2 = %B\n", ptc.CP2);
    element_clear(denominator_1);
    element_clear(numerator_1);
    element_clear(denominator_2);
    element_clear(numerator_2);
    for (auto it = Ei.begin(); it != Ei.end(); ++it)
    {
        element_clear(&(*it));
    }
    Ei.clear();
    for (auto it = Di.begin(); it != Di.end(); ++it)
    {
        element_clear(&(*it));
    }
    Di.clear();
    for (auto it = lambda.begin(); it != lambda.end(); ++it)
    {
        element_clear(&(*it));
    }
    lambda.clear();
    for (auto it = ky_1.begin(); it != ky_1.end(); ++it)
    {
        element_clear(&(*it));
    }
    ky_1.clear();
    for (auto it = ky_2.begin(); it != ky_2.end(); ++it)
    {
        element_clear(&(*it));
    }
    ky_2.clear();
    for (auto it = ws_1.begin(); it != ws_1.end(); ++it)
    {
        element_clear(&(*it));
    }
    ws_1.clear();
    for (auto it = ws_1.begin(); it != ws_1.end(); ++it)
    {
        element_clear(&(*it));
    }
    ws_2.clear();


}

void ABE2OD::Transform2(TC &tc, KeyTuple::HK &hk, PTC &ptc, pairing_t _pairing)
{
    element_t result_1, result_2;
    element_init_GT(result_1, _pairing);
    element_init_GT(result_2, _pairing);
    element_pow_zn(result_1, ptc.CP1, hk.gamma_1);
    element_pow_zn(result_2, ptc.CP2, hk.gamma_2);

    if (element_cmp(result_1, result_2) == 0)
    {
        //printf("ptc.CP1 ^ hk.gamma_1 and ptc.CP2 ^ hk.gamma_2 are equal\n");
    } else
    {
        printf("ptc.CP1 ^ hk.gamma_1 and ptc.CP2 ^ hk.gamma_2 are not equal\n");
        return;
    }

    element_init_GT(tc.T0, _pairing);
    element_init_GT(tc.T2, _pairing);

    // T0
    element_set(tc.T0, ptc.C0);

    // T1
    tc.T1 = ptc.C1;

    // T2
    element_set(tc.T2, result_1);
    element_clear(result_1);
    element_clear(result_2);
}


string ABE2OD::Dec(KeyTuple::DK &dk, TC &tc, pairing_t _pairing)
{

    element_t R, temp_result;
    element_init_GT(R, _pairing);
    element_init_GT(temp_result, _pairing);
    element_pow_zn(temp_result, tc.T2, dk.beta);

    element_set(R, tc.T0);
    element_div(R, R, temp_result);//R
    element_printf("dec R = %B\n", R);

    string M;
    string hash_R = elementToHash(R);
    cout << "dec hash_R = " << hash_R << '\n';
    string xorResult = xorHashes(hash_R, tc.T1);
    M = xorResult;
    cout << "dec M1 = " << M << '\n';


    // s
    element_t s;
    element_init_Zr(s, _pairing);
    element_from_hash(s, (void *) (hash_R + M).c_str(), (hash_R + M).length());
    element_printf("dec s = %B\n", s);

    element_t result_1, result_2;
    element_init_GT(result_1, _pairing);
    element_init_GT(result_2, _pairing);

    element_pow_zn(result_1, pk.eggalpha, s);
    element_set(result_2, result_1);
    element_mul(result_1, result_1, R);

    if (element_cmp(result_1, tc.T0) != 0)
    {
        element_printf("R* e(g,g)^αs = %B\n", result_1);
        element_printf("tc.T0 = %B\n", tc.T0);
        return "";
    } else element_printf("tc.T0 = R* e(g,g)^αs = %B\n", result_1);

    if (element_cmp(result_2, temp_result) != 0)
    {
        element_printf("tc.T2^beta = %B\n", temp_result);
        element_printf("e(g,g)^αs = %B\n", result_2);
        return "";
    } else element_printf("tc.T2^beta = e(g,g)^αs = %B\n", result_2);
    element_clear(R);
    element_clear(temp_result);
    element_clear(s);
    element_clear(result_1);
    element_clear(result_2);
    return M;
}

ABE2OD::ABE2OD()
{}

ABE2OD::~ABE2OD()
{}

void ABE2OD::showkeys()
{
    element_printf("Public Key:\n g = %B\n e(g,g)^alpha = %B\n g^a = %B\n", pk.g, pk.eggalpha, pk.ga);
    element_printf("Master Secret Key:\n g^alpha = %B\n", msk.galpha);
}

void ABE2OD::showkeytuple(KeyTuple &keytuple)
{
    element_printf("Decryption key dk.beta = %B\n", keytuple.dk.beta);
    element_printf("Revocation key hk.gamma_1 = %B\n", keytuple.hk.gamma_1);
    element_printf("Revocation key hk.gamma_2 = %B\n", keytuple.hk.gamma_2);

    element_printf("T1 Transformation key: \nK1 = %B\nL1 = %B\n", keytuple.tk_1.K, keytuple.tk_1.L);
    for (auto e: keytuple.tk_1.Ky)
    {
        element_printf("Ky_1: %s \t %B\n", e.first.c_str(), &e.second);
    }
    element_printf("T2 Transformation key: \nK2 = %B\nL2 = %B\n", keytuple.tk_2.K, keytuple.tk_2.L);
    for (auto e: keytuple.tk_2.Ky)
    {
        element_printf("Ky_2: %s \t %B\n", e.first.c_str(), &e.second);
    }
}

void ABE2ODSPACE::ABE2OD::showcipher(ABE2ODSPACE::Ciphertext &cipher)
{
    element_printf("CO = %B\n", cipher.C0);
    cout << "C1 = " << cipher.C1 << '\n';
    element_printf("C2 = %B\n", cipher.C2);

    assert(cipher.Ei.size() == cipher.Di.size());
    assert(cipher.Ei.size() == cipher.lambda.size());

    for (int i = 0; i < cipher.Ei.size(); i++)
    {
        element_printf("D%d = %B\n", i, &cipher.Di[i]);
        element_printf("E%d = %B\n", i, &cipher.Ei[i]);
        element_printf("lambda%d = %B\n", i, &cipher.lambda[i]);
    }
}


void ABE2OD::showPTC(ABE2ODSPACE::PTC &ptc)
{
    element_printf("C0 = %B\n", ptc.C0);
    cout << "C1 = " << ptc.C1 << '\n';
    element_printf("CP1 = %B\n", ptc.CP1);
    element_printf("CP2 = %B\n", ptc.CP2);
}

void ABE2OD::showTC(ABE2ODSPACE::TC &tc)
{
    element_printf("T0 = %B\n", tc.T0);
    cout << "T1 = " << tc.T1 << '\n';
    element_printf("T2 = %B\n", tc.T2);
}
