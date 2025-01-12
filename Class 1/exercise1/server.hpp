/*
** EPITECH PROJECT, 2024
** C1
** File description:
** server
*/

#ifndef SERVER_HPP_
#define SERVER_HPP_

#include "user.hpp"
#include  <vector>
#include <random>
#include "openssl/sha.h"
#include <sstream>
#include <iomanip>

class Server {
    public:
        Server() {};
        ~Server() {};
        void login() {
            std::string username;
            std::string password;
            std::cout << "Please enter your username" << std::endl;
            std::cin >> username;
            std::cout << "Please enter your password" << std::endl;
            std::cin >> password;
            for (auto user : _users) {
                if (user.getUsername() == username) {
                    std::string saltedPassword = password + user.getSalt();
                    std::string hashedPassword = generateHashedPassword(saltedPassword);
                    if (hashedPassword == user.getHash()) {
                        std::cout << "Login successful" << std::endl;
                        std::cout << "Welcome " << user.getUsername() << std::endl;
                        std::cout << "Your name is " << user.getName() << std::endl;
                        return;
                    }
                }
            }
            std::cout << "Login failed" << std::endl;
        }
        void registerUser() {
            std::string username;
            std::string password;
            std::string name;
            std::cout << "Please enter your username" << std::endl;
            std::cin >> username;
            std::cout << "Please enter your password" << std::endl;
            std::cin >> password;
            std::cout << "Please enter your name" << std::endl;
            std::cin >> name;
            if (checkIfUserExists(username)) {
                std::cout << "User already exists" << std::endl;
                return;
            }


            std::string salt = generateSalt();
            std::string saltedPassword = password + salt;

            User user(username, generateHashedPassword(saltedPassword), name, salt);
            _users.push_back(user);
            std::cout << "User registered !" << std::endl;
        }

        bool checkIfUserExists(std::string username) {
            for (auto user : _users) {
                if (user.getUsername() == username) {
                    return true;
                }
            }
            return false;
        }

        std::string generateSalt() {
            std::string salt = "";
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 9);
            for (int i = 0; i < 10; i++) {
                salt += std::to_string(dis(gen));
            }
            return salt;
        }
        std::string generateHashedPassword(std::string saltedPassword) {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, saltedPassword.c_str(), saltedPassword.size());
            SHA256_Final(hash, &sha256);
            std::stringstream ss;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            }
            return ss.str();

        }

    private:
        std::vector<User> _users;
};

#endif /* !SERVER_HPP_ */
