#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <iomanip>
#include <omp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

// 辅助函数：将字节数组转换为十六进制字符串
string bytes_to_hex(const unsigned char *data, size_t length)
{
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < length; ++i)
    {
        ss << setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

// SHA256哈希函数
string hash_data(const string &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
}

// 构建Merkle树
vector<vector<string>> build_merkle_tree(const vector<string> &leaves)
{
    vector <vector<string>> tree;
    vector <string> current_level;

    // 哈希所有叶子节点
    for (const auto &leaf: leaves)
    {
        current_level.push_back(hash_data(leaf));
    }
    tree.push_back(current_level);

    // 自底向上构建树
    while (current_level.size() > 1)
    {
        vector <string> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2)
        {
            string combined;
            if (i + 1 < current_level.size())
            {
                combined = current_level[i] + current_level[i + 1];
            } else
            {
                combined = current_level[i] + current_level[i];
            }
            next_level.push_back(hash_data(combined));
        }
        tree.push_back(next_level);
        current_level = next_level;
    }

    return tree;
}

// 获取认证路径
vector<string> get_authentication_path(size_t index, const vector<vector<string>> &tree)
{
    vector <string> path;
    for (size_t level = 0; level < tree.size() - 1; ++level)
    {
        size_t sibling_index = index ^ 1;
        if (sibling_index < tree[level].size())
        {
            path.push_back(tree[level][sibling_index]);
        }
        index /= 2;
    }
    return path;
}

// 验证签名
bool verify_signature(const string &public_key_str, const string &message, const string &signature_str)
{
    BIO *bio = BIO_new_mem_buf(public_key_str.c_str(), public_key_str.size());
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa)
    {
        return false;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(message.c_str()), message.size(), hash);

    vector<unsigned char> signature(signature_str.begin(), signature_str.end());
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                            signature.data(), signature.size(), rsa);

    RSA_free(rsa);
    return result == 1;
}

// 验证Merkle树根节点
bool verify_merkle_root(const string &leaf_hash, const string &root, const vector<string> &auth_path, size_t index)
{
    string current_hash = leaf_hash;
    for (const auto &sibling_hash: auth_path)
    {
        if (index % 2 == 0)
        {
            current_hash = hash_data(current_hash + sibling_hash);
        } else
        {
            current_hash = hash_data(sibling_hash + current_hash);
        }
        index /= 2;
    }
    return current_hash == root;
}

void Basic_experimental_performance(const int h, const int num_keys, const int epoch)
{

    // 初始化随机数生成器
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, num_keys - 1);

    // 生成RSA密钥对
    auto start_time = omp_get_wtime();
    vector < RSA * > private_keys;
    vector <string> public_keys;

    for (int i = 0; i < num_keys; ++i)
    {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);

        // 使用新API生成密钥
        if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1)
        {
            ERR_print_errors_fp(stderr);
            BN_free(e);
            RSA_free(rsa);
            continue;  // 跳过当前迭代
        }
        BN_free(e);
        private_keys.push_back(rsa);

        // 导出公钥
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio, rsa);
        char *pub_key;
        long pub_len = BIO_get_mem_data(bio, &pub_key);
        public_keys.emplace_back(pub_key, pub_len);
        BIO_free(bio);
    }

    // 构建Merkle树
    auto merkle_tree = build_merkle_tree(public_keys);
    string merkle_root = merkle_tree.back()[0];
    cout << "Merkle Root: " << merkle_root << '\n';

    auto end_time = omp_get_wtime();
    double merkle_tree_gen_time = end_time - start_time;

    double signature_gen_time = 0;
    double merkle_ver_time = 0;
    string message = "APTX4869";

    for (int i = 0; i < epoch; ++i)
    {
        // 随机选择一个密钥对
        int random_index = dis(gen);
        RSA *private_key = private_keys[random_index];
        string public_key = public_keys[random_index];

        // 签名生成
        start_time = omp_get_wtime();

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char *>(message.c_str()), message.size(), hash);

        unsigned char sig[256];
        unsigned int sig_len;
        RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, private_key);
        string signature(reinterpret_cast<char *>(sig), sig_len);

        // 获取认证路径
        auto authentication_path = get_authentication_path(random_index, merkle_tree);
        end_time = omp_get_wtime();
        signature_gen_time += end_time - start_time;

//        cout << "Message: " << message << '\n';
//        cout << "Signature: " << bytes_to_hex(reinterpret_cast<const unsigned char *>(signature.c_str()), signature.size()) << '\n';
//        cout << "Authentication Path: ";
//        for (const auto &node: authentication_path)
//        {
//            cout << node << " ";
//        }
//        cout << '\n';

        // 验证签名
        start_time = omp_get_wtime();
        bool verification_result = verify_signature(public_key, message, signature);
        if (!verification_result)
        {
            cout << "Signature Verification: " << (verification_result ? "Success" : "Failed") << '\n';
            exit(-1);
        }

        // 验证Merkle树根节点
        string user_leaf_hash = hash_data(public_key);
        bool merkle_verification = verify_merkle_root(user_leaf_hash, merkle_root, authentication_path, random_index);
        end_time = omp_get_wtime();
        merkle_ver_time += end_time - start_time;

        if (!merkle_verification)
        {
            cout << "Merkle Root Verification: " << (merkle_verification ? "Success" : "Failed") << '\n';
            exit(-1);
        }

    }

    // 释放RSA密钥
    for (auto key: private_keys)
    {
        RSA_free(key);
    }

    cout << fixed << setprecision(4);
    cout << "Merkle Tree Generation Time: " << merkle_tree_gen_time << " s" << '\n';
    cout << "Signature Generation Time: " << (signature_gen_time / epoch * 1000) << " ms" << '\n';
    cout << "Merkle Root Verification Time: " << (merkle_ver_time / epoch * 1000) << " ms" << '\n';
}

int main()
{
    const int h = 10; // Merkle树高度
    const int num_keys = 1 << h; // 密钥对数量
    const int epoch = 100; // 测试次数
    Basic_experimental_performance(h, num_keys, epoch);
    return 0;

    // 初始化随机数生成器
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, num_keys - 1);

    // 生成RSA密钥对
    auto start_time = omp_get_wtime();
    vector < RSA * > private_keys;
    vector <string> public_keys;

    for (int i = 0; i < num_keys; ++i)
    {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);

        // 使用新API生成密钥
        if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1)
        {
            ERR_print_errors_fp(stderr);
            BN_free(e);
            RSA_free(rsa);
            continue;  // 跳过当前迭代
        }
        BN_free(e);
        private_keys.push_back(rsa);

        // 导出公钥
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio, rsa);
        char *pub_key;
        long pub_len = BIO_get_mem_data(bio, &pub_key);
        public_keys.emplace_back(pub_key, pub_len);
        BIO_free(bio);
    }

    // 构建Merkle树
    auto merkle_tree = build_merkle_tree(public_keys);
    string merkle_root = merkle_tree.back()[0];
    cout << "Merkle Root: " << merkle_root << '\n';

    auto end_time = omp_get_wtime();
    double merkle_tree_gen_time = end_time - start_time;

    double signature_gen_time = 0;
    double merkle_ver_time = 0;
    string message = "APTX4869";


    const int coreNum = omp_get_num_procs(); // 获得处理器个数
    cout << "Max core number is: " << coreNum << '\n';

    vector<int> test_threads = {1, 6, 12, 24}; // 目标测试线程数


    for (int threads: test_threads)
    {
        cout << "\n[Benchmark] 线程数: " << threads << '\n';
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

                    // 随机选择一个密钥对
                    int random_index = dis(gen);
                    RSA *private_key = private_keys[random_index];
                    string public_key = public_keys[random_index];

                    // 签名生成
                    double sign_start = omp_get_wtime();
                    unsigned char hash[SHA256_DIGEST_LENGTH];
                    SHA256(reinterpret_cast<const unsigned char *>(message.c_str()), message.size(), hash);
                    unsigned char sig[256];
                    unsigned int sig_len;
                    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, private_key);
                    string signature(reinterpret_cast<char *>(sig), sig_len);
                    auto authentication_path = get_authentication_path(random_index, merkle_tree); // 获取认证路径
                    local_sign += omp_get_wtime() - sign_start;

                    // 验证阶段
                    double verify_start = omp_get_wtime();

                    //-- 验证签名
                    bool verification_result = verify_signature(public_key, message, signature);
                    if (!verification_result)
                    {
                        cout << "Signature Verification: " << (verification_result ? "Success" : "Failed") << '\n';
                        exit(-1);
                        error_count++;
                    }
                    //-- 验证Merkle树根节点
                    string user_leaf_hash = hash_data(public_key);
                    bool merkle_verification = verify_merkle_root(user_leaf_hash, merkle_root, authentication_path, random_index);
                    if (!merkle_verification)
                    {
                        cout << "Merkle Root Verification: " << (merkle_verification ? "Success" : "Failed") << '\n';
                        exit(-1);
                        error_count++;
                    }
                    local_verify += omp_get_wtime() - verify_start;

                    if (!verification_result || !merkle_verification)
                    {
#pragma omp critical
                        cerr << "验证失败 (线程 " << omp_get_thread_num()
                             << " 迭代 " << i << ")\n";
                        error_count++;
                    }
                } catch (...)
                {
#pragma omp critical
                    cerr << "异常发生在线程 " << omp_get_thread_num() << '\n';
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
        cout << "└─ 错误次数:     " << error_count << '\n';
        cout << "─────────────────────────────────────────\n";
    }

    return 0;
}