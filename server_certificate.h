#ifndef SERVER_CERTIFICATE_H
#define SERVER_CERTIFICATE_H

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>
#include <fstream>
#include <iostream>

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

inline void load_server_certificate(boost::asio::ssl::context& ctx)
{
    std::string const cert = read_file("cert.pem");
    std::string const key = read_file("key.pem");
    std::string const dh = read_file("dh.pem");
/*
    ctx.set_password_callback(
          [](std::size_t,
              boost::asio::ssl::context_base::password_purpose)
          {
              return "test";
          });
*/
    ctx.set_options(
      boost::asio::ssl::context::default_workarounds |
      boost::asio::ssl::context::no_sslv2 |
      boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(
      boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(
      boost::asio::buffer(key.data(), key.size()),
      boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh(
      boost::asio::buffer(dh.data(), dh.size()));

}

#endif // SERVER_CERTIFICATE_H
