#include <iostream>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <omp.h>
#include <vector>
#include <iomanip>

using namespace std;

/**
 * 将GT元素转换为Zr元素的辅助函数
 * @param zr_out
 * @param gt_in
 * @param pairing
 */
void gt_to_zr(element_t zr_out, element_t gt_in, pairing_t pairing)
{
    size_t len = element_length_in_bytes(gt_in);
    unsigned char *buf = new unsigned char[len];
    element_to_bytes(buf, gt_in);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, len, hash);
    delete[] buf;

    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_import(hash_mpz, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    mpz_t order;
    mpz_init(order);
    mpz_set(order, pairing->r);
    mpz_mod(hash_mpz, hash_mpz, order);
    element_set_mpz(zr_out, hash_mpz);

    mpz_clear(hash_mpz);
    mpz_clear(order);
}

// 系统参数设置函数
void setup(element_t s, element_t P_pub, element_t P, pairing_t pairing)
{
    element_init_Zr(s, pairing);
    element_random(s);

    element_init_G1(P_pub, pairing);
    element_mul_zn(P_pub, P, s);
}

// 密钥提取函数
void extract(element_t r, element_t R, element_t Q_ID, element_t S_ID, element_t s, element_t P, pairing_t pairing)
{
    element_init_Zr(r, pairing);
    element_random(r);

    element_init_G1(R, pairing);
    element_mul_zn(R, P, r);

    element_init_G1(Q_ID, pairing);
    element_set(Q_ID, R);

    element_init_G1(S_ID, pairing);
    element_mul_zn(S_ID, Q_ID, s);
}

// 签名生成函数
void signing(element_t N, element_t theta, element_t sigma, element_t omega, element_t epsilon, element_t z,
             element_t r, element_t S_ID, element_t Q_ID,
             element_t x, element_t y, pairing_t pairing)
{

    element_init_G1(N, pairing);
    element_random(N);

    element_init_G1(theta, pairing);
    element_set(theta, N);
    element_mul_zn(theta, theta, r);

    element_init_GT(sigma, pairing);
    pairing_apply(sigma, N, S_ID, pairing);

    element_init_GT(omega, pairing);
    pairing_apply(omega, N, Q_ID, pairing);

    element_t left, right;
    element_init_GT(left, pairing);
    element_init_GT(right, pairing);
    element_pow_zn(left, omega, x);
    element_pow_zn(right, sigma, y);
    element_mul(left, left, right);

    element_init_Zr(z, pairing);
    gt_to_zr(z, left, pairing);

    element_init_G1(epsilon, pairing);
    element_pow_zn(epsilon, S_ID, z);

    element_clear(left);
    element_clear(right);
}


// 签名验证函数
bool verification(element_t P, element_t P_pub, element_t Q_ID,
                  element_t theta, element_t N, element_t R, element_t sigma,
                  element_t epsilon, element_t z, pairing_t pairing)
{
    element_t miu;
    element_init_GT(miu, pairing);
    pairing_apply(miu, P_pub, Q_ID, pairing);

    element_t e_theta_P, e_N_R, e_P_epsilon, e_N_epsilon;
    element_init_GT(e_theta_P, pairing);
    element_init_GT(e_N_R, pairing);
    element_init_GT(e_P_epsilon, pairing);
    element_init_GT(e_N_epsilon, pairing);
    pairing_apply(e_theta_P, theta, P, pairing);
    pairing_apply(e_N_R, N, R, pairing);
    pairing_apply(e_P_epsilon, P, epsilon, pairing);
    pairing_apply(e_N_epsilon, N, epsilon, pairing);

    element_t right_1, right_2;
    element_init_GT(right_1, pairing);
    element_init_GT(right_2, pairing);
    element_pow_zn(right_1, miu, z);
    element_pow_zn(right_2, sigma, z);

    bool result = (element_cmp(e_theta_P, e_N_R) == 0) &&
                  (element_cmp(e_P_epsilon, right_1) == 0) &&
                  (element_cmp(e_N_epsilon, right_2) == 0);

    // 清理临时变量
    element_clear(miu);
    element_clear(e_theta_P);
    element_clear(e_N_R);
    element_clear(e_P_epsilon);
    element_clear(e_N_epsilon);
    element_clear(right_1);
    element_clear(right_2);

    return result;
}

void Basic_experimental_performance(pairing_t pairing)
{
    int epoch = 100;
    double start_time, end_time = 0;
    double average_time_sign = 0;
    double average_time_verify = 0;
    for (int i = 0; i < epoch; i++)
    {
        element_t P;
        element_init_G1(P, pairing);
        element_random(P);

        element_t x, y;
        element_init_Zr(x, pairing);
        element_init_Zr(y, pairing);
        element_random(x);
        element_random(y);

        // Setup
        element_t s, P_pub;
        setup(s, P_pub, P, pairing);

        // Extract
        element_t r, R, Q_ID, S_ID;
        extract(r, R, Q_ID, S_ID, s, P, pairing);

        // Signing

        start_time = omp_get_wtime();
        element_t N, theta, sigma, omega, epsilon, z;
        signing(N, theta, sigma, omega, epsilon, z, r, S_ID, Q_ID, x, y, pairing);
        average_time_sign += (omp_get_wtime() - start_time) * 1000;

        // Verification
        start_time = omp_get_wtime();
        bool verify_result = verification(P, P_pub, Q_ID, theta, N,
                                          R, sigma, epsilon, z, pairing);
        average_time_verify += (omp_get_wtime() - start_time) * 1000;

        if (!verify_result)
        {
            cerr << "Verification error at iteration " << i << '\n';
            exit(-1);
        }

        // 清理资源
        element_clear(P);
        element_clear(s);
        element_clear(P_pub);
        element_clear(x);
        element_clear(y);
        element_clear(r);
        element_clear(R);
        element_clear(Q_ID);
        element_clear(S_ID);
        element_clear(N);
        element_clear(theta);
        element_clear(sigma);
        element_clear(omega);
        element_clear(epsilon);
        element_clear(z);
    }

    printf("[sign] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_sign / epoch);
    printf("[verify] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_verify / epoch);
}

void benchmark_test(pairing_t pairing,
                    element_t P, element_t P_pub, element_t r,
                    element_t R, element_t Q_ID, element_t S_ID,
                    element_t x, element_t y,
                    const vector<int> &test_threads)
{
    /***
     * OpenMP并行环境下时间统计的经典陷阱
     * 1.时间叠加效应
     * 在多线程环境下，reduction(+:sign_time)会将所有线程的签名时间相加。6个线程各执行1秒，实际物理时间1秒，但统计得到6秒，导致出现327%的虚假占比。
     * 2.物理时间与CPU时间混淆
     * total_time测量的是物理时间（墙钟时间），而各阶段时间是所有线程CPU时间的总和，二者单位不一致。
     * 正确的时间关系：max_sign + max_verify ≈ total_time
     * 并行系统的实际耗时取决于最慢的线程（木桶效应）
     * @return
     */
    // 记录不同线程数下的签名和验证时间
    //    for (int threads: test_threads)
    //    {
    //        cout << "\n[Benchmark] Threads: " << threads << '\n';
    //        omp_set_num_threads(threads);
    //
    //        // 重置计时器
    //        double loop_start = omp_get_wtime();
    //        double sign_time = 0.0;
    //        double verify_time = 0.0;
    //
    //#pragma omp parallel for reduction(+:sign_time, verify_time)
    //        for (int i = 0; i < 1000; i++)
    //        {
    //            // 签名阶段计时
    //            double sign_start = omp_get_wtime();
    //            element_t N, theta, sigma, omega, epsilon, z;
    //            element_init_G1(N, pairing);
    //            element_init_G1(theta, pairing);
    //            element_init_GT(sigma, pairing);
    //            element_init_GT(omega, pairing);
    //            element_init_G1(epsilon, pairing);
    //            element_init_Zr(z, pairing);
    //
    //            signing(N, theta, sigma, omega, epsilon, z, r, S_ID, Q_ID, x, y, pairing);
    //            sign_time += omp_get_wtime() - sign_start;
    //
    //            // 验证阶段计时
    //            double verify_start = omp_get_wtime();
    //            bool verify_result = verification(P, P_pub, Q_ID, theta, N,
    //                                              R, sigma, epsilon, z, pairing);
    //            verify_time += omp_get_wtime() - verify_start;
    //
    //            if (!verify_result)
    //            {
    //#pragma omp critical
    //                {
    //                    cerr << "Error: Verification failed at iteration " << i
    //                         << " (Thread " << omp_get_thread_num() << ")" << '\n';
    //                }
    //                exit(EXIT_FAILURE);
    //            }
    //
    //            // 清理资源
    //            element_clear(N);
    //            element_clear(theta);
    //            element_clear(sigma);
    //            element_clear(omega);
    //            element_clear(epsilon);
    //            element_clear(z);
    //        }
    //
    //        // 输出结果
    //        double total_time = omp_get_wtime() - loop_start;
    //        cout << "  Total time:    " << total_time * 1000 << " ms" << '\n';
    //        cout << "  Signing time:  " << sign_time * 1000 << " ms ("
    //             << (sign_time/threads / total_time) * 100 << "%)" << '\n';
    //        cout << "  Verify time:   " << verify_time * 1000 << " ms ("
    //             << (verify_time/threads / total_time) * 100 << "%)" << '\n';
    //        cout << "  Throughput:    " << 1000 / (total_time * 1000) << " ops/sec" << '\n';
    //        cout << "--------------------------------------------------" << '\n';
    //    }
}

int main()
{
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_t pairing;
    pairing_init_pbc_param(pairing, param);
//    Basic_experimental_performance(pairing);

    element_t P;
    element_init_G1(P, pairing);
    element_random(P);

    element_t x, y;
    element_init_Zr(x, pairing);
    element_init_Zr(y, pairing);
    element_random(x);
    element_random(y);

    // Setup
    element_t s, P_pub;
    setup(s, P_pub, P, pairing);

    // Extract
    element_t r, R, Q_ID, S_ID;
    extract(r, R, Q_ID, S_ID, s, P, pairing);


    const int coreNum = omp_get_num_procs(); // 获得处理器个数
    cout << "Max core number is: " << coreNum << '\n';

    vector<int> test_threads = {1, 6, 12, 18, 24}; // 目标测试线程数


    for (int threads: test_threads)
    {
        cout << "\n[Benchmark] 线程数: " << threads << endl;
        omp_set_num_threads(threads);

        // 计时变量（使用最大线程耗时统计）
        double total_start = omp_get_wtime(); // 真实物理时间
        double max_sign_time = 0.0; // 捕获的是系统的真实签名瓶颈时间
        double max_verify_time = 0.0;
        int error_count = 0;

#pragma omp parallel reduction(max:max_sign_time, max_verify_time) \
                         reduction(+:error_count)
        {
            double local_sign = 0, local_verify = 0; // 单个线程执行 1000/threads 次迭代的总时间

#pragma omp for nowait
            for (int i = 0; i < 1000; i++)
            {
                try
                {
                    // 签名阶段
                    double sign_start = omp_get_wtime();
                    element_t N, theta, sigma, omega, epsilon, z;
                    signing(N, theta, sigma, omega, epsilon, z, r, S_ID, Q_ID, x, y, pairing);
                    local_sign += omp_get_wtime() - sign_start;

                    // 验证阶段
                    double verify_start = omp_get_wtime();
                    bool verify_result = verification(P, P_pub, Q_ID, theta, N, R, sigma, epsilon, z, pairing);
                    local_verify += omp_get_wtime() - verify_start;

                    if (!verify_result)
                    {
#pragma omp critical
                        cerr << "验证失败 (线程 " << omp_get_thread_num()
                             << " 迭代 " << i << ")\n";
                        error_count++;
                    }

                    // 资源清理
                    element_clear(N);
                    element_clear(theta);
                    element_clear(sigma);
                    element_clear(omega);
                    element_clear(epsilon);
                    element_clear(z);
                } catch (...)
                {
#pragma omp critical
                    cerr << "异常发生在线程 " << omp_get_thread_num() << endl;
                    error_count++;
                }
            }

            // 更新各线程最大耗时
            max_sign_time = max(max_sign_time, local_sign);
            max_verify_time = max(max_verify_time, local_verify);
        }

        // 结果计算
        double total_time = omp_get_wtime() - total_start;
        double throughput = 1000 / (total_time * 1000); // 实际吞吐量

        // 结果输出
        cout << "├─ 总耗时:       " << total_time * 1000 << " ms\n";
        cout << "├─ 签名耗时:     " << max_sign_time * 1000 << " ms (" << (max_sign_time / total_time) * 100 << "%)\n";
        cout << "├─ 验证耗时:     " << max_verify_time * 1000 << " ms (" << (max_verify_time / total_time) * 100 << "%)\n";
        cout << "├─ 系统吞吐量:   " << throughput << " ops/sec\n";
        cout << "└─ 错误次数:     " << error_count << endl;
        cout << "─────────────────────────────────────────\n";
    }
    // 清理配对参数
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 0;
}