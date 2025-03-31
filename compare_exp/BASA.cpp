#include <iostream>
#include <pbc/pbc.h>
#include <omp.h>

using namespace std;


struct PK
{
    element_t g_1;
    element_t g_2;
};

void IBSA(element_t P_pub_s, PK pk, string M, pairing_t pairing)
{
//    elemenmt_t g;
//    element_init_GT(g, pairing);
//    pairing_apply(g, pk.g_1, P_pub_s, pairing);
//
//    element_t r;
//    element_init_Zr(r, pairing);
//    element_random(r);
//    element_printf("r = %B\n", r);
//
//    elemenmt_t w;
//    element_init_GT(g, pairing);
//    element_pow_zn(w, g, r);
//
//    element_t h, l;

}

void IBVA()
{

}

int main()
{
    // 初始化椭圆曲线
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_t pairing;
    pairing_init_pbc_param(pairing, param);


    PK pk;
    element_init_G1(pk.g_1, pairing);
    element_init_G2(pk.g_2, pairing);
    element_random(pk.g_1);
    element_random(pk.g_2);
    element_printf("g_1 = %B\n", pk.g_1);
    element_printf("g_2 = %B\n", pk.g_2);


    // signature master key pair (ks,P_pub_s)
    element_t ks; // signature master private key
    element_init_Zr(ks, pairing);
    element_random(ks);
    element_printf("ks = %B\n", ks);
    element_t P_pub_s;
    element_init_G2(P_pub_s, pairing);
    element_mul_zn(P_pub_s, pk.g_2, ks);
    element_printf("P_pub_s = %B\n", P_pub_s);


    double start_time, end_time = 0;
    double average_time_IBSA = 0;
    double average_time_IBVA = 0;
    int epoch = 1;
    // IBSA
    start_time = omp_get_wtime();
//    IBSA();
    end_time = omp_get_wtime();
    average_time_IBSA += (end_time - start_time) * 1000;

    // IBVA
    start_time = omp_get_wtime();
    IBVA();
    end_time = omp_get_wtime();
    average_time_IBVA += (end_time - start_time) * 1000;

    printf("[IBSA] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_IBSA / epoch);
    printf("[IBVA] ---- %d次 平均耗时 %.4f ms\n", epoch, average_time_IBVA / epoch);

    return 0;
}