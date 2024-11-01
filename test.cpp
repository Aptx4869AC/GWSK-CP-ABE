#include <iostream>
#include <omp.h>
#include <time.h>
#include <random>
#include "include/ABE/ABE2OD.h"
#include "include/pbc/pbc_test.h"
#include "include/PicoSHA2/picosha2.h"

using namespace std;
using namespace ABE2ODSPACE;

string generateBinaryHash(size_t bitLength)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, 1);

    string hash;
    do
    {
        // 生成二进制哈希字符串
        hash.clear();
        for (size_t i = 0; i < bitLength - 1; i++) // 减去1，因为最高位需要填充1
        {
            int bit = dist(gen);
            hash += std::to_string(bit);
        }
        hash = "1" + hash; // 最高位填充1
    } while (hash.back() == '0'); // 检查最低位是否为1
    return hash;
}


string generateString(int length)
{
    stringstream ss;
    ss << "(";
    for (int i = 1; i <= length; ++i)
    {
        ss << "A" << i;
        if (i < length)
        {
            ss << ",";
        }
    }
    ss << ")";
    return ss.str();
}


int main(int argc, char *argv[])
{
    int epoch = 10;
    double start_time, end_time;
    double average_time_Setup = 0, average_time_Enc = 0, average_time_Keygen = 0, average_time_PDec = 0, average_time_TDec = 0;

    for (int i = 0; i < epoch; i++)
    {

//        const char *param = "type a\n"
//                            "q 13443769915192326887\n"
//                            "h 24133562481384\n"
//                            "r 557057\n"
//                            "exp2 19\n"
//                            "exp1 15\n"
//                            "sign1 1\n"
//                            "sign0 1";
////        const char *param =
////                "type a\n"
////                "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
////                "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
////                "r 730750818665451621361119245571504901405976559617\n"
////                "exp2 159\n"
////                "exp1 107\n"
////                "sign1 1\n"
////                "sign0 1";
//
//
//        // 初始化pbc_param_t
//        pbc_param_t par;
//        pbc_param_init_set_str(par, param);
//        // 初始化pairing_t
//        pairing_t pairing;
//        pairing_init_pbc_param(pairing, par);


//        // 初始化pbc_param_t结构体
//        pbc_param_t param;
//
//        // 生成一个类型为A的椭圆曲线参数，给定一个80位的安全等级和一个256位的素数q
//        pbc_param_init_a_gen(param, 20, 64);
//
//        // 输出生成的参数（可选）
//        pbc_param_out_str(stdout, param);
//        // 初始化pairing_t结构体
//        pairing_t pairing;
//        pairing_init_pbc_param(pairing, param);

        pbc_param_t param;
        pbc_param_init_a_gen(param, 160, 512);
        pairing_t pairing;
        pairing_init_pbc_param(pairing, param);

        // Setup 初始化
        ABE2OD abe2od;
        start_time = omp_get_wtime();
        abe2od.Setup(pairing);
        end_time = omp_get_wtime();
        average_time_Setup += (end_time - start_time) * 1000;

        abe2od.showkeys();
        printf("-------------------------------------------------------------------------\n");


        // KeyGen
//        string attribute_str = "(A,B,C,D,F)";
        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,10)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,20)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,30)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,40)";
//        string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,A41,A42,A43,A44,A45,A46,A47,A48,A49,A50,50)";
        cout << "attribute_str = " << attribute_str << '\n';
        KeyTuple keytuple;

        start_time = omp_get_wtime();
        abe2od.KeyGen(keytuple, attribute_str, pairing);
        end_time = omp_get_wtime();
        average_time_Keygen += (end_time - start_time) * 1000;

        abe2od.showkeytuple(keytuple);
        printf("-------------------------------------------------------------------------\n");


        // Enc
        // 生成LSSS矩阵
//        string access_policy = "((A,B,2),(C,D,E,3),(F,(G,H,2),1),2)";
        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40)";
//        string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26,A27,A28,A29,A30,A31,A32,A33,A34,A35,A36,A37,A38,A39,A40,A41,A42,A43,A44,A45,A46,A47,A48,A49,A50)";
        cout << "access_policy = " << access_policy << '\n';
        LSSS lsss(access_policy);

        // 生成消息M
        element_t M;
        element_init_GT(M, pairing);
        element_random(M);
        element_printf("M = %B\n", M);

        Ciphertext cipher;
        start_time = omp_get_wtime();
        abe2od.Enc(cipher, M, lsss, pairing);
        end_time = omp_get_wtime();
        average_time_Enc += (end_time - start_time) * 1000;

        abe2od.showcipher(cipher);
        printf("-------------------------------------------------------------------------\n");



        //Transform1
        PTC ptc;
        start_time = omp_get_wtime();
        abe2od.PDec(ptc, keytuple.tk, cipher, pairing);
        end_time = omp_get_wtime();
        average_time_PDec += (end_time - start_time) * 1000;

        abe2od.showPTC(ptc);
        printf("-------------------------------------------------------------------------\n");


        // Decrypt
        element_t M1;
        element_init_GT(M1, pairing);

        start_time = omp_get_wtime();
        abe2od.TDec(M1, keytuple.sk, ptc, pairing);
        end_time = omp_get_wtime();
        average_time_TDec += (end_time - start_time) * 1000;

        element_printf("M1 = %B\n", M1);

        // 判断M和M1是否一致
        if (element_cmp(M, M1) != 0)
        {
            element_printf("Before encryption: M = %B\n", M);
            element_printf("After encryption: M1 = %B\n", M1);
            cout << "错误：M与M1不一致" << '\n';
            return -1;  // 返回非零值表示出错
        }

        printf("-------------------------------------------------------------------------\n");
    }

    printf("[KGC，步骤一] %d次 Setup平均耗时 %.6f ms\n", epoch, average_time_Setup / epoch);
    printf("[KGC，步骤二] %d次 Keygen平均耗时 %.6f ms\n", epoch, average_time_Keygen / epoch);
    printf("[投标人，步骤三] %d次 Enc平均耗时 %.6f ms\n", epoch, average_time_Enc / epoch);
    printf("[区块链，步骤四] %d次 PDec平均耗时 %.6f ms\n", epoch, average_time_PDec / epoch);
    printf("[招标人，步骤五] %d次 TDec平均耗时 %.6f ms\n", epoch, average_time_TDec / epoch);

    printf("Info: exp successfully returned.\n");
    return 0;
}

