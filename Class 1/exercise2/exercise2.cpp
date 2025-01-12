/*
** EPITECH PROJECT, 2024
** C1
** File description:
** exercise2
*/

#include "tester.hpp"

int main(void)
{
    std::cout << "Please enter the filename of the passwords file" << std::endl;
    std::string filename;
    std::cin >> filename;
    Tester tester;
    tester.loadPasswordsFile(filename);
    std::cout << "Please enter the hashed password" << std::endl;
    std::string hashedPassword;
    std::cin >> hashedPassword;
    tester.findPassword(hashedPassword);
    return 0;
}