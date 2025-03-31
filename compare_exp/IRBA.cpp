#include <iostream>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <omp.h>

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

int main()
{
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_t pairing;
    pairing_init_pbc_param(pairing, param);

    int epoch = 100;
    double start_time, end_time = 0;
    double average_time_sign = 0;
    double average_time_verify = 0;
    for (int i = 0; i < epoch; i++)
    {
        element_t P;
        element_init_G1(P, pairing);
        element_random(P);
//        element_printf("P = %B\n", P);

        element_t x, y;
        element_init_Zr(x, pairing);
        element_init_Zr(y, pairing);
        element_random(x);
        element_random(y);
//        element_printf("x = %B\n", x);
//        element_printf("y = %B\n", y);

        // Setup
        element_t s;
        element_init_Zr(s, pairing);
        element_t P_pub;
        element_init_G1(P_pub, pairing);
        element_random(s);
        element_mul_zn(P_pub, P, s);
//        element_printf("s = %B\n", s);
//        element_printf("P_pub = %B\n", P_pub);

        // Extract
        element_t r, R;
        element_init_Zr(r, pairing);
        element_init_G1(R, pairing);
        element_random(r);
        element_mul_zn(R, P, r);
//        element_printf("r = %B\n", r);
//        element_printf("R = %B\n", R);

        element_t Q_ID, S_ID;
        element_init_G1(Q_ID, pairing);
        element_init_G1(S_ID, pairing);
        element_set(Q_ID, R);
        element_mul_zn(S_ID, Q_ID, s);
//        element_printf("Q_ID = %B\n", Q_ID);
//        element_printf("S_ID = %B\n", S_ID);

//        cout << "----------------------------------------------------------\n";
        // Signing
        start_time = omp_get_wtime();
        element_t theta, sigma, omega, epsilon, z;
        element_init_G1(theta, pairing);
        element_init_GT(sigma, pairing);
        element_init_GT(omega, pairing);
        element_init_G1(epsilon, pairing);
        element_init_Zr(z, pairing);

        element_t N;
        element_init_G1(N, pairing);
        element_random(N);
//        element_printf("N = %B\n", N);
        element_set(theta, N);
        element_mul_zn(theta, theta, r);
//        element_printf("theta = %B\n", theta);

        pairing_apply(sigma, N, S_ID, pairing);
        pairing_apply(omega, N, Q_ID, pairing);
//        element_printf("sigma = %B\n", sigma);
//        element_printf("omega = %B\n", omega);

        element_t left, right;
        element_init_GT(left, pairing);
        element_init_GT(right, pairing);
        element_pow_zn(left, omega, x);
        element_pow_zn(right, sigma, y);
        element_mul(left, left, right);
//        element_printf("left = %B\n", left);
        gt_to_zr(z, left, pairing);
//        element_printf("z = %B\n", z);

        element_pow_zn(epsilon, S_ID, z);
//        element_printf("epsilon = %B\n", epsilon);
        end_time = omp_get_wtime();
        average_time_sign += (end_time - start_time) * 1000;

        cout << "----------------------------------------------------------\n";
        // Verification
        start_time = omp_get_wtime();
        element_t miu;
        element_init_GT(miu, pairing);
        pairing_apply(miu, P_pub, Q_ID, pairing);

        element_t e_theta_P;
        element_t e_N_R;
        element_t e_P_epsilon;
        element_t e_N_epsilon;
        element_init_GT(e_theta_P, pairing);
        element_init_GT(e_N_R, pairing);
        element_init_GT(e_P_epsilon, pairing);
        element_init_GT(e_N_epsilon, pairing);
        pairing_apply(e_theta_P, theta, P, pairing);
        pairing_apply(e_N_R, N, R, pairing);
        pairing_apply(e_P_epsilon, P, epsilon, pairing);
        pairing_apply(e_N_epsilon, N, epsilon, pairing);


        element_t right_1;
        element_t right_2;
        element_init_GT(right_1, pairing);
        element_init_GT(right_2, pairing);
        element_pow_zn(right_1, miu, z);
        element_pow_zn(right_2, sigma, z);

        if (element_cmp(e_theta_P, e_N_R) == 0)
        {
            printf("等式1 Success\n");
        } else
        {
            printf("等式1 error\n");
            return -1;  // 返回非零值表示出错
        }
        if (element_cmp(e_P_epsilon, right_1) == 0)
        {
            printf("等式2 Success\n");
        } else
        {
            printf("等式2 error\n");
            return -1;  // 返回非零值表示出错
        }
        if (element_cmp(e_N_epsilon, right_2) == 0)
        {
            printf("等式3 Success\n");
        } else
        {
            printf("等式3 error\n");
            return -1;  // 返回非零值表示出错
        }
        end_time = omp_get_wtime();
        average_time_verify += (end_time - start_time) * 1000;
    }

    printf("[sign] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_sign / epoch);
    printf("[verify] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_verify / epoch);

    return 0;
}