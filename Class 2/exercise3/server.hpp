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
#include <iostream>
#include <chrono>
#include <ctime>

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
                        addOTP(user);
                        std::cout << "Please enter the OTP code" << std::endl;
                        if (checkOTP(user)) {
                            // std::cout << "[DEBUG] OTP: " << user.getOtp() << std::endl;
                            std::cout << "Login successful" << std::endl;
                            std::cout << "Welcome " << user.getUsername() << std::endl;
                            std::cout << "Your name is " << user.getName() << std::endl;
                            return;
                        } else {
                            std::cout << "Login failed, invalid OTP code" << std::endl;
                            return;
                        }
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
        std::string generateOtp(std::string hash, User &user) {
            auto now = std::chrono::system_clock::now();

            std::string hashAndTime = hash + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
            unsigned char otpHash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, hashAndTime.c_str(), hashAndTime.size());
            SHA256_Final(otpHash, &sha256);
            std::stringstream ss;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)otpHash[i];
            }
            std::string otp = ss.str();
            //get the last 6 bytes of the hash
            std::string lastBytes = otp.substr(otp.size() - 6);
            //return its hexa value
            std::stringstream stream;
            stream << std::hex << lastBytes;
            std::string result( stream.str() );
            user.setOtpHash(otp);
            return result;
        }
        void addOTP(User &user) {
            std::string otp = generateOtp(user.getHash(), user);
            std::cout << "[DEBUG] Your OTP is " << otp << std::endl;
        }
        bool checkOTP(User &user) {
            std::cout << "Please enter your OTP" << std::endl;
            std::string otpToCheck;
            std::cin >> otpToCheck;
            std::string otpHash = user.getOtp();
            //Check if the OTP is valid by checking if the 6 bytes of the OTP are the same as the last 6 bytes of the hash
            std::string otpHash6bytes = otpHash.substr(otpHash.size() - 6);
            //Convert otpTocCheck to decimal
            std::stringstream stream;
            stream << std::hex << otpToCheck;
            std::string result( stream.str() );
            //check if the last 6 bytes of the hash are the same as the otp
            if (result == otpHash6bytes) {
                std::cout << "OTP is valid" << std::endl;
                return true;
            }
            return false;
        }

    private:
        std::vector<User> _users;
};

#endif /* !SERVER_HPP_ */
