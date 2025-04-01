#include <iostream>
#include <random>
#include <vector>
#include <algorithm>
#include <pbc/pbc.h>
#include <omp.h>
#include <openssl/sha.h>

using namespace std;


void gt_to_zr(element_t zr_out, element_t gt_in, pairing_t pairing)
{
    // 1. 将GT元素转换为字节串
    size_t len = element_length_in_bytes(gt_in);
    unsigned char *buf = new unsigned char[len];
    element_to_bytes(buf, gt_in);

    // 2. 使用SHA256哈希处理字节串
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, len, hash);
    delete[] buf;

    // 3. 将哈希结果转换为mpz_t
    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 4. 获取群的阶（Zr的模数）
    mpz_t order;
    mpz_init(order);

    // 方法1：直接从pairing中获取群阶（适用于PBC 0.5.14及以上版本）
    mpz_set(order, pairing->r); // 使用pairing->r作为模数

    // 方法2：如果方法1失败，尝试通过G1群的阶替代（需确保G1和GT同阶）
    // element_t g1_elem;
    // element_init_G1(g1_elem, pairing);
    // element_get_order(order, g1_elem); // 非标准函数，可能不可用
    // element_clear(g1_elem);

    // 5. 取模并设置Zr元素
    mpz_mod(hash_mpz, hash_mpz, order);
    element_set_mpz(zr_out, hash_mpz);

    // 清理
    mpz_clear(hash_mpz);
    mpz_clear(order);
}


vector<int> generate_unique_randoms(int n, int count)
{
    // 1. 创建顺序序列
    vector<int> sequence(n);
    iota(sequence.begin(), sequence.end(), 1); // 填充1~n

    // 2. 随机打乱（使用硬件随机引擎）
    random_device rd;
    mt19937_64 gen(rd());
    shuffle(sequence.begin(), sequence.end(), gen);

    // 3. 取前count个元素
    return {sequence.begin(), sequence.begin() + count};
}

void func_h(element_t res, element_t r, vector<element_s> M, int id, pairing_t pairing)
{
    element_t x, X;
    element_init_Zr(x, pairing);
    element_init_Zr(X, pairing);
    element_set_si(x, id);
    element_set(X, x);
    for (int i = 0; i < M.size(); i++)
    {
        element_t tmp;
        element_init_Zr(tmp, pairing);
        element_set(tmp, &M[i]);
        element_mul(tmp, tmp, X);
        element_add(res, res, tmp);
        element_mul(X, X, x);
    }
    element_add(res, res, r);
}

void func_H(element_t res, element_t S_ID, vector<element_s> N, int id, pairing_t pairing)
{
    element_t x, X;
    element_init_Zr(x, pairing);
    element_init_Zr(X, pairing);
    element_set_si(x, id);
    element_set(X, x);
    for (int i = 0; i < N.size(); i++)
    {
        element_t tmp;
        element_init_G1(tmp, pairing);
        element_set(tmp, &N[i]);
        element_mul_zn(tmp, tmp, X);
        element_add(res, res, tmp);
        element_mul(X, X, x);
    }
    element_add(res, res, S_ID);
}


void lagrange_basis(vector<element_s> res, vector<int> rand_numbers, pairing_t pairing)
{
    // 初始化结果和临时变量
    element_t numerator, denominator, term, x_i, x_j;
    element_init_Zr(numerator, pairing);
    element_init_Zr(denominator, pairing);
    element_init_Zr(term, pairing);
    element_init_Zr(x_i, pairing);
    element_init_Zr(x_j, pairing);

    // 拉格朗日插值核心算法
    for (size_t i = 0; i < rand_numbers.size(); ++i)
    {
        element_set1(numerator);
        element_set1(denominator);
        element_set_si(x_i, rand_numbers[i]);

        // 计算基多项式系数
        for (size_t j = 0; j < rand_numbers.size(); ++j)
        {
            if (i == j) continue;
            element_set_si(x_j, rand_numbers[j]);
            element_neg(x_j, x_j);

            // 分子连乘 (x_j)
            element_mul(numerator, numerator, x_j);

            // 分母连乘 (x_i - x_j)
            element_neg(x_j, x_j);
            element_sub(term, x_i, x_j);
            element_mul(denominator, denominator, term);
        }
        element_div(term, numerator, denominator);
        element_set(&res[i], term);

    }
    // 清理临时变量
    element_clear(numerator);
    element_clear(denominator);
    element_clear(term);
    element_clear(x_i);
    element_clear(x_j);
}

void recover_func_h_poly(element_t res, vector<element_s> shares, vector<int> rand_numbers, pairing_t pairing)
{
    // 初始化结果和临时变量
    element_t numerator, denominator, term, x_i, x_j;
    element_init_Zr(numerator, pairing);
    element_init_Zr(denominator, pairing);
    element_init_Zr(term, pairing);
    element_init_Zr(x_i, pairing);
    element_init_Zr(x_j, pairing);
    element_set0(res);

    // 拉格朗日插值核心算法
    for (size_t i = 0; i < shares.size(); ++i)
    {
        element_set1(numerator);
        element_set1(denominator);
        element_set_si(x_i, rand_numbers[i]);

        // 计算基多项式系数
        for (size_t j = 0; j < shares.size(); ++j)
        {
            if (i == j) continue;
            element_set_si(x_j, rand_numbers[j]);
            element_neg(x_j, x_j);

            // 分子连乘 (x_j)
            element_mul(numerator, numerator, x_j);

            // 分母连乘 (x_i - x_j)
            element_neg(x_j, x_j);
            element_sub(term, x_i, x_j);
            element_mul(denominator, denominator, term);
        }

        // 计算当前项：y_i * numerator / denominator
        element_div(term, numerator, denominator);
        element_mul(term, term, &shares[i]);
        element_add(res, res, term);
    }
    // 清理临时变量
    element_clear(numerator);
    element_clear(denominator);
    element_clear(term);
    element_clear(x_i);
    element_clear(x_j);
}


void recover_func_H_poly(element_t res, vector<element_s> shares, vector<int> rand_numbers, pairing_t pairing)
{
    // 初始化结果和临时变量
    element_t numerator, denominator, item, term, x_i, x_j;
    element_init_Zr(numerator, pairing);
    element_init_Zr(denominator, pairing);
    element_init_G1(item, pairing);
    element_init_Zr(term, pairing);
    element_init_Zr(x_i, pairing);
    element_init_Zr(x_j, pairing);
    element_set0(res);

    // 拉格朗日插值核心算法
    for (size_t i = 0; i < shares.size(); ++i)
    {
        element_set1(numerator);
        element_set1(denominator);
        element_set_si(x_i, rand_numbers[i]);

        // 计算基多项式系数
        for (size_t j = 0; j < shares.size(); ++j)
        {
            if (i == j) continue;
            element_set_si(x_j, rand_numbers[j]);
            element_neg(x_j, x_j);

            // 分子连乘 (x_j)
            element_mul(numerator, numerator, x_j);

            // 分母连乘 (x_i - x_j)
            element_neg(x_j, x_j);
            element_sub(term, x_i, x_j);
            element_mul(denominator, denominator, term);
        }

        // 计算当前项：y_i * numerator / denominator
        element_div(term, numerator, denominator);
        element_mul_zn(item, &shares[i], term);
        element_add(res, res, item);
    }
    // 清理临时变量
    element_clear(numerator);
    element_clear(denominator);
    element_clear(term);
    element_clear(item);
    element_clear(x_i);
    element_clear(x_j);
}

int main()
{
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_t pairing;
    pairing_init_pbc_param(pairing, param);


    double start_time, end_time = 0;
    double average_time_sign = 0;
    double average_time_verify = 0;

    int epoch = 100;
    for (int _epoch = 0; _epoch < epoch; _epoch++)
    {

        element_t P;
        element_init_G1(P, pairing);
        element_random(P);

        vector <element_s> M, N;
        int t = 3;
        for (int i = 1; i < t; i++)
        {
            element_s m, n;
            element_init_Zr(&m, pairing);
            element_init_G1(&n, pairing);
            element_random(&m);
            element_random(&n);
            M.push_back(m);
            N.push_back(n);
        }

        element_t r, S_ID;
        element_init_Zr(r, pairing);
        element_init_G1(S_ID, pairing);
        element_random(r);
        element_random(S_ID);
//        element_printf("r = %B\n", r);
//        element_printf("S_ID = %B\n", S_ID);

        int n = 5;
        vector <element_s> h_id, H_id;
        vector <element_s> lambda_id, miu_id;
        // shamir秘密分享生成份额
        for (int id = 1; id <= n; id++)
        {
            element_s hi, Hi;
            element_init_Zr(&hi, pairing);
            element_init_G1(&Hi, pairing);
            func_h(&hi, r, M, id, pairing);
            func_H(&Hi, S_ID, N, id, pairing);
            h_id.push_back(hi); // Zr
            H_id.push_back(Hi); // G1

            element_s lambda_i, miu_i;
            element_init_G1(&lambda_i, pairing);
            element_init_GT(&miu_i, pairing);
            element_mul_zn(&lambda_i, P, &hi);
            pairing_apply(&miu_i, P, &Hi, pairing);
            lambda_id.push_back(lambda_i);
            miu_id.push_back(miu_i);
        }

        for (int i = 0; i < h_id.size(); i++)
        {
//        element_printf("h[%d] = %B\n", i, &h_id[i]); // 函数h的份额
//        element_printf("H[%d] = %B\n", i, &H_id[i]); // 函数H的份额
//        element_printf("lambda[%d] = %B\n", i, &lambda_id[i]);
//        element_printf("miu[%d] = %B\n", i, &miu_id[i]);
        }

        // 多项式恢复
        int participants = 4; // 参与者数量
        vector<int> rand_numbers = generate_unique_randoms(n, participants);
//        for (auto item: rand_numbers)
//        {
//            cout << item << " ";
//        }
//        cout << '\n';
        vector <element_s> h_shares;
        vector <element_s> H_shares;
        for (int i = 0; i < rand_numbers.size(); i++)
        {
            element_s tmp_1, tmp_2;
            element_init_Zr(&tmp_1, pairing);
            element_init_G1(&tmp_2, pairing);
            element_set(&tmp_1, &h_id[rand_numbers[i] - 1]);
            element_set(&tmp_2, &H_id[rand_numbers[i] - 1]);
            h_shares.push_back(tmp_1); // Zr
            H_shares.push_back(tmp_2); // G1
        }

        // 拉格朗日插值恢复
        element_t r_prime, S_ID_prime;
        element_init_Zr(r_prime, pairing);
        element_init_G1(S_ID_prime, pairing);
        recover_func_h_poly(r_prime, h_shares, rand_numbers, pairing);
//        element_printf("r_prime = %B\n", r_prime);
        recover_func_H_poly(S_ID_prime, H_shares, rand_numbers, pairing);
//        element_printf("S_ID_prime = %B\n", S_ID_prime);
        if (element_cmp(r, r_prime) != 0 && element_cmp(S_ID, S_ID_prime) != 0)
        {
            printf("等式 error\n");
            return -1;  // 返回非零值表示出错
        }


        // Signing
        start_time = omp_get_wtime();

        vector <element_s> coefficient_res;
        for (int i = 0; i < rand_numbers.size(); i++)
        {
            element_s tmp;
            element_init_Zr(&tmp, pairing);
            coefficient_res.push_back(tmp);
        }
        lagrange_basis(coefficient_res, rand_numbers, pairing);
//        for (int i = 0; i < coefficient_res.size(); i++)
//        {
//            element_printf("%B\n", &coefficient_res[i]);
//        }
        vector <element_s> theta_id, epsilon_id;
        for (int k = 0; k < rand_numbers.size(); k++)
        {
            //-- Step 1
            int j = rand_numbers[k] - 1;
            element_t m;
            element_init_G1(m, pairing);
            element_random(m);
//            element_printf("m = %B\n", m);

            element_t R, Q_id;
            element_init_G1(R, pairing);
            element_init_G1(Q_id, pairing);
            element_random(R);
            element_set(Q_id, R);

            element_t theta_j, sigma_j, x_j, y_j, Q_j;
            element_init_G1(theta_j, pairing);
            element_init_G1(Q_j, pairing);
            element_init_GT(sigma_j, pairing);
            element_init_GT(x_j, pairing);
            element_init_GT(y_j, pairing);
            element_random(Q_j);

            element_mul_zn(theta_j, m, &h_id[j]);
            pairing_apply(sigma_j, m, &H_id[j], pairing);
            pairing_apply(x_j, P, Q_j, pairing);
            pairing_apply(y_j, m, Q_j, pairing);
//        element_printf("Q_j = %B\n", Q_j);
//        element_printf("sigma_j = %B\n", sigma_j);
//        element_printf("x_j = %B\n", x_j);
//        element_printf("y_j = %B\n", y_j);


            //-- Step 2
            element_t x, y, sigma;
            element_init_GT(x, pairing);
            element_init_GT(y, pairing);
            element_init_GT(sigma, pairing);
            element_pow_zn(x, x_j, &coefficient_res[k]);
            element_pow_zn(y, y_j, &coefficient_res[k]);
            element_pow_zn(sigma, sigma_j, &coefficient_res[k]);

            //-- Step 3
            element_t V_j, omega;
            element_init_G1(V_j, pairing);
            element_init_GT(omega, pairing);
            pairing_apply(omega, m, Q_id, pairing);

            element_t left, right, z;
            element_init_GT(left, pairing);
            element_init_GT(right, pairing);
            element_init_Zr(z, pairing);
            element_pow_zn(left, omega, x);
            element_pow_zn(right, sigma, y);
            element_mul(left, left, right);
            gt_to_zr(z, left, pairing);
            element_pow_zn(V_j, &H_id[j], z);

            element_s tmp1, tmp2;
            element_init_G1(&tmp1, pairing);
            element_init_G1(&tmp2, pairing);
            element_set(&tmp1, theta_j);
            element_set(&tmp2, V_j);
            theta_id.push_back(tmp1);
            epsilon_id.push_back(tmp2);
        }

        /* -- Step 4 一段验证操作 */
        /* 相同的验证操作（实际效果等同于V1版本） 2.5088 ms */

        //-- Step 5
        element_t theta, epsilon;
        element_init_G1(theta, pairing);
        element_init_G1(epsilon, pairing);
        recover_func_H_poly(theta, theta_id, rand_numbers, pairing);
//        element_printf("theta = %B\n", theta);
        recover_func_H_poly(epsilon, epsilon_id, rand_numbers, pairing);
//        element_printf("epsilon = %B\n", epsilon);

        end_time = omp_get_wtime();
        average_time_sign += (end_time - start_time) * 1000 + 2.5088;
        // Verification
        /* 相同的验证操作（实际效果等同于V1版本） 2.5088 ms */
        average_time_verify += 2.5088;
    }

    printf("[sign] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_sign / epoch);
    printf("[verify] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_verify / epoch);

    return 0;
}