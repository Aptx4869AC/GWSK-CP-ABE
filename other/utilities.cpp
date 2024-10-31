//
// Created by Xiaoguo on 2022/7/17.
//

#include "../include/ABE/utilities.h"
#include <vector>
#include <algorithm>
#include <string>
#include <pbc/pbc.h>
void trim(std::string& str)
{
    int index = 0;
    if(!str.empty())
    {
        while (std::string::npos != (index = str.find(' ', index)))
        {
            str.erase(index, 1);
        }
    }
}

/*
 * [Input]
 *      str: a string represents the attributes, e.g. string str = "(A, B, G, I, J, L)";
 * [output]
 *      attr_Set : return all attributes, e.g. A B G I J L;
 */
void string2attribute_Set(vector<string> &attr_set, const string &_str)
{
    string str = _str;
    // parse string
    trim(str);
    str.erase(0,1);
    str.pop_back();

    string substr;
    int ct = 0;
    for(int i = 0; i<str.size(); i++)
    {
        if(str.at(i) == ',')
        {
            attr_set.push_back(substr);
            substr.clear();
        } else {
            substr += str.at(i);
        }
    }
    if(substr.size() != 0)  attr_set.push_back(substr);
}

/*
 * [Input]
 *      attr: a set of attributes
 *      labels: a vector of attributes; [1....n] -- > {attribute set}
 * [output]
 *      I : return all index i such that labels[i] is in attr;
 * */
void Fetchrows(vector<int> &I, vector<string> &attr, vector<string> &labels)
{
    for (int i = 0; i < labels.size(); ++i) {
        if(attr.end() != find(attr.begin(),attr.end(), labels[i]))
            I.push_back(i);
    }
}

void showmatrix(vector<vector<double>> &matrix)
{
    int rownumber = matrix.size();
    int colnumber = matrix[0].size();
    for (int i = 0; i < rownumber; ++i)
    {
        for (int j = 0; j < colnumber; ++j)
        { cout << matrix[i][j] << '\t'; }
        cout << endl;
    }
}


void solve(vector<element_s> &res, vector<vector<element_s>> matrix, pairing_t pairing)
{
    for (int j = 0; j < matrix[0].size()-1; ++j) // 枚举列
    {
        // cout << "-------- 第 " << j <<'/' << matrix[0].size()-1 << " 列 ---------" << endl;
        int i;
        for (i = j; i < matrix.size(); ++i) // 找到非0元素
        {
            if(!element_is0(&matrix[i][j])) break;
            /*else {
                element_printf("A[%d][%d]=%B\n", i, j, &matrix[i][j]);
            }*/
        }

        if (matrix.size() == i) // 无解的情形
        {
            continue;
        }
        for (int k = 0; k < matrix[i].size(); ++k) // 把非0元素所在行交换到当前行
            swap(matrix[i][k], matrix[j][k]);
        for (int k = matrix[j].size()-1; k >= j; --k) // 把当前行除以A[j][j]，令A[j][j]归一，注意循环顺序
        {
            // element_printf("A[%d][%d]=%B\n", j, j, &matrix[j][j]);
            // element_printf("A[%d][%d]\n", j, k);
            element_div(&matrix[j][k], &matrix[j][k], &matrix[j][j]);
        }
        for (int i = 0; i < matrix.size(); ++i) // 对其他行消元
        {
            if (i != j){
                for (int k = matrix[i].size()-1; k >= j; --k) // 注意循环顺序
                {
                    element_s tmp;
                    element_init_Zr(&tmp, pairing);
                    element_mul(&tmp, &matrix[j][k], &matrix[i][j]);
                    element_sub(&matrix[i][k], &matrix[i][k], &tmp);
                    element_clear(&tmp);
                    //cout << matrix[i][k] << '\t';
                }   //cout << endl;
            }
            //showmatrix(matrix);
        }

        //showmatrix(matrix);
    }

    for (int i = 0; i < matrix.size(); ++i) {
        res.push_back(matrix.at(i).at(matrix.at(i).size() - 1));
    }
}

void solve(vector<double> &res, vector<vector<double>> matrix)
{
    //showmatrix(matrix);
    // Gauss
    for (int j = 0; j < matrix[0].size()-1; ++j) // 枚举列
    {
        //cout << "-------- 第 " << j <<'/' << matrix[0].size()-1 << " 列 ---------" << endl;
        int i;
        for (i = j; i < matrix.size(); ++i) // 找到非0元素
            if (matrix[i][j])
                break;
        if (matrix.size() == i) // 无解的情形
        {
            continue;
        }
        for (int k = 0; k < matrix[i].size(); ++k) // 把非0元素所在行交换到当前行
            swap(matrix[i][k], matrix[j][k]);
        for (int k = matrix[j].size()-1; k >= j; --k) // 把当前行除以A[j][j]，令A[j][j]归一，注意循环顺序
            matrix[j][k] /= matrix[j][j];
        //showmatrix(matrix);
        for (int i = 0; i < matrix.size(); ++i) // 对其他行消元
        {
            if (i != j){
                for (int k = matrix[i].size()-1; k >= j; --k) // 注意循环顺序
                {
                    matrix[i][k] -= matrix[j][k] * matrix[i][j];
                    //cout << matrix[i][k] << '\t';
                }   //cout << endl;
            }
        }
        //showmatrix(matrix);
    }

    for (int i = 0; i < matrix.size(); ++i) {
        res.push_back(matrix.at(i).at(matrix.at(i).size() - 1));
    }
}
