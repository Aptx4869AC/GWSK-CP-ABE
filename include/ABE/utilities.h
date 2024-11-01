

#ifndef SECRETSHARING_UTILITIES_H
#define SECRETSHARING_UTILITIES_H

#include <string>
#include <iostream>
#include <vector>

using namespace std;

void trim(std::string& str);

/*
 * [Input]
 *      str: a string represents the attributes, e.g. string str = "(A, B, G, I, J, L)";
 * [output]
 *      attr_Set : return all attributes, e.g. A B G I J L;
 */
void string2attribute_Set(vector<string> &attr_set, const string &str);

/*
 * [Input]
 *      attr: a set of attributes
 *      labels: a vector of attributes; [1....n] -- > {attribute set}
 * [output]
 *      I : return all index i such that labels[i] is in attr;
 * */
void Fetchrows(vector<int> &I, vector<string> &attr, vector<string> &labels);

void showmatrix(vector<vector<double>> &matrix);

#include <pbc/pbc.h>
void solve(vector<element_s> &res, vector<vector<element_s>> matrix, pairing_t pairing);

void solve(vector<double> &res, vector<vector<double>> matrix);

#endif //SECRETSHARING_UTILITIES_H
