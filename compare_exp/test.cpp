#include <iostream>
#include <omp.h>
#include <vector>

using namespace std;

// 快速幂取模运算函数
long long fastPower(long long a, long long b, long long m)
{
    long long result = 1;
    a %= m; // 先对 a 取模，防止溢出

    while (b > 0)
    {
        if (b & 1)
        { // 如果 b 的最低位是 1
            result = (result * a) % m;
        }
        a = (a * a) % m; // 平方底数
        b >>= 1; // 右移 b，相当于 b / 2
    }
    return result;
}

int main()
{
    const int coreNum = omp_get_num_procs(); // 获得处理器个数
    cout << "Max core number is: " << coreNum << endl;

    vector<int> test_threads = {1, 6,  12,  18,  24}; // 目标测试线程数

    // 测试不同线程数的性能
    for (int threads: test_threads)
    {
        cout << "Testing with thread number: " << threads << endl;

        double start_time, end_time;
        omp_set_num_threads(threads); // 修正变量名错误

        start_time = omp_get_wtime();

#pragma omp parallel for
        for (int i = 0; i < 1000000; i++)
        {
            fastPower(2, 5000000, 1000000007); // 使用更清晰的常量表示
        }

        // 确保所有线程执行完毕
#pragma omp barrier

        end_time = omp_get_wtime();

        cout << "Execution time: " << (end_time - start_time) * 1000 << " ms" << endl;
        cout << "------------------------------------------------\n";
    }
    return 0;
}