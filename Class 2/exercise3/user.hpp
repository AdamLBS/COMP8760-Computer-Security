/*
** EPITECH PROJECT, 2024
** C1
** File description:
** user
*/

#ifndef USER_HPP_
#define USER_HPP_

#include <iostream>

class User {
    public:
        User(std::string username, std::string hash, std::string name, std::string salt) {
            setUsername(username);
            setHash(hash);
            setName(name);
            setSalt(salt);
        };
        ~User() {};
        void setUsername(std::string username) {
            _username = username;
        };
        void setHash(std::string hash) {
            _hash = hash;
        };
        std::string getUsername() {
            return _username;
        };
        std::string getHash() {
            return _hash;
        };

        std::string getSalt() {
            return _salt;
        };

        std::string getName() {
            return _name;
        };

        void setName(std::string name) {
            _name = name;
        };

        void setSalt(std::string salt) {
            _salt = salt;
        };

        void setOtpHash(std::string otpHash) {
            _otpHash = otpHash;
        };

        std::string getOtp() {
            return _otpHash;
        };


    private:
        std::string _username;
        std::string _hash;
        std::string _name;
        std::string _salt;
        std::string _otpHash;

};


#endif /* !USER_HPP_ */
