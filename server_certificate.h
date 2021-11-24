#ifndef SERVER_CERTIFICATE_H
#define SERVER_CERTIFICATE_H

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <pwd.h>
#include <string>
#include <sstream>

std::string read_file(std::string const& path)
{
    std::string s_out;
    std::ifstream in;

    in.open(path);
    if (in.fail())
        throw std::runtime_error("не удалось открыть файл " + path);

    for(;;)
    {
        std::array<char, 1024> buf;

        in.read(buf.data(), buf.size());
        s_out.append(buf.data(), in.gcount());

        if (in.eof())
            break;

        if (in.fail())
            throw std::runtime_error("не удалось прочитать файл");
    }
    return s_out;
}


void change_user(std::string const& user_name)
{
    passwd* pw = getpwnam(user_name.c_str());
    if (pw == nullptr)
        throw std::runtime_error ("Не найден пользователь " + user_name);

    if (setgid(pw->pw_gid) != 0)
    {
        std::stringstream ss;
        ss << "Не удалось изменить группу на " << pw->pw_gid;
        throw std::runtime_error (ss.str());
    }

    if (setuid(pw->pw_uid) != 0)
    {
        std::stringstream ss;
        ss << "Не удалось изменить пользователя на " << pw->pw_uid;
        throw std::runtime_error (ss.str());
    }
}

#endif // SERVER_CERTIFICATE_H
