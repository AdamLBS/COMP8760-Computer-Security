/*
** EPITECH PROJECT, 2024
** C1
** File description:
** exercise1
*/

#include <iostream>
#include "server.hpp"

int main(void)
{
    Server server;
    while (1) {
        std::cout << "Please select an option" << std::endl;
        std::cout << "1: Login" << std::endl;
        std::cout << "2: Register" << std::endl;
        std::cout << "Other: Quit" << std::endl;
        int choice;
        std::cin >> choice;
        switch (choice) {
            case 1:
                server.login();
                break;
            case 2:
                server.registerUser();
                break;
            default:
                std::cout << "Quit" << std::endl;
                return 0;
        }
    }
}