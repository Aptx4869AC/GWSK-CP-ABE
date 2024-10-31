//
// Created by Xiaoguo on 2022/7/12.
//

#ifndef SECRETSHARING_LSSS_H
#define SECRETSHARING_LSSS_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>
#include <unordered_map>

#include <pbc/pbc.h>

using namespace std;

class LSSS {

public:
    vector<vector<int>> M;
    vector<string> rho;
    string access_policy;

    LSSS();
    LSSS(string access_control);
    ~LSSS();

    void initialize(string &access_control);
    bool satisfy(string&);
    bool isSatisfy(string, pairing_t pairing);
    void show();
    void generateShares(vector<element_s> &shares, vector<element_s> &secret, pairing_t pairing);
    void recoverSecret(element_s &secret, vector<element_s> &shares, pairing_t pairing);
    void findVector(vector<element_s> &vec, const string, pairing_t pairing);
    void getValidShares(vector<element_s> &valid_Shares, vector<element_s> &shares, string, pairing_t pairing);
    void getValidSharesExt(vector<element_s> &valid_Shares, vector<element_s> &valid_Ci, vector<element_s> &valid_Di, vector<element_s> &valid_kx,
                           vector<element_s> &shares, vector<element_s> &Ci, vector<element_s> &Di, unordered_map<string, element_s> &kx,
                           string, pairing_t pairing);
protected:
    void parseString(stack<pair<vector<int>, string>> &stack1, pair<vector<int>, string> &pair1, int& counter);

};


#endif //SECRETSHARING_LSSS_H
