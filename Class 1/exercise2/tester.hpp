/*
** EPITECH PROJECT, 2024
** C1
** File description:
** tester
*/

#ifndef TESTER_HPP_
#define TESTER_HPP_

#include <iostream>
#include <vector>
#include <fstream>
#include "openssl/sha.h"
#include <sstream>
#include <iomanip>

class Tester {
    public:
        Tester() {};
        ~Tester() {};
        void loadPasswordsFile(const std::string &filename) {
            std::ifstream file(filename);
            std::string line;
            while (std::getline(file, line)) {
                std::string password = line;
                passwords.push_back(line);
            }
        }

        void findPassword(const std::string &password) {
            for (auto pass : passwords) {
                if (generateHashedPassword(pass) == password) {
                    std::cout << "Password found: " << pass << std::endl;
                    return;
                }
            }
        }

        std::string generateHashedPassword(std::string password) {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, password.c_str(), password.size());
            SHA256_Final(hash, &sha256);
            std::stringstream ss;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            }
            return ss.str();

        }
    private: 
        std::vector<std::string> passwords;
};

#endif /* !TESTER_HPP_ */
