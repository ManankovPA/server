#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <iostream>
#include <vector>
#include <atomic>
#include <string>
#include "cpp_signals.h"
#include "server_certificate.h"
#include "worker_thread_manager.h"
using namespace boost::asio::ip;

struct server_params
{
    tcp::endpoint endpoint;
    size_t max_idle_threads;

    std::string certificate;
    std::string private_key;
    std::string dh_params;
    std::string token;
};

struct server
{
    typedef boost::beast::http::response<boost::beast::http::string_body> response_t;
    typedef boost::beast::http::request<boost::beast::http::string_body> request_t;

    server(boost::asio::io_context& ctx, server_params const& params)
        :acceptor(ctx, params.endpoint)
        ,connection_count(0)
        ,ssl_ctx(boost::asio::ssl::context::tlsv12)
        ,manager(params.max_idle_threads, [this]{thread_proc(); })
    {
        load_server_certificate(ssl_ctx, params);
        manager.start();
    }

    void thread_proc();

    tcp::socket accept(tcp::endpoint& endpoint);

    response_t generate_response(request_t const & req);
    response_t generate_bad_request_response(request_t const& req, std::string const& str);


    void load_server_certificate(boost::asio::ssl::context& ctx, server_params const& params)
    {
        ctx.set_options(
          boost::asio::ssl::context::default_workarounds |
          boost::asio::ssl::context::no_sslv2 |
          boost::asio::ssl::context::single_dh_use);

        std::string const& cert = params.certificate;
        ctx.use_certificate_chain(
          boost::asio::buffer(cert.data(), cert.size()));

        std::string const& key = params.private_key;
        ctx.use_private_key(
          boost::asio::buffer(key.data(), key.size()),
          boost::asio::ssl::context::file_format::pem);

        std::string const& dh = params.dh_params;
        ctx.use_tmp_dh(
          boost::asio::buffer(dh.data(), dh.size()));
    }

private:

    tcp::acceptor acceptor;
    std::atomic<size_t> connection_count;
    boost::asio::ssl::context ssl_ctx;
    worker_thread_manager manager;
    friend struct accepting_thread_guard;
};

server::response_t server::generate_response(request_t const& req)
{
    if(req.method() != boost::beast::http::verb::get &&
       req.method() != boost::beast::http::verb::head)
    {
        return generate_bad_request_response(req, "Unknown HTTP-method");
    }

    response_t res(boost::beast::http::status::ok, req.version());
    res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(boost::beast::http::field::content_type, "text/plain");
    res.keep_alive(req.keep_alive());
    res.body() = "Hello world";
    res.prepare_payload();
    return res;
}

server::response_t server::generate_bad_request_response(request_t const& req, std::string const& why)
{
    response_t res{boost::beast::http::status::bad_request, req.version()};
    res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(boost::beast::http::field::content_type, "text/plain");
    res.keep_alive(req.keep_alive());
    res.body() = why;
    res.prepare_payload();
    return res;
}

void server::thread_proc()
{
    for(;;)
    {
        try
        {
            tcp::endpoint endpoint;
            tcp::socket s = accept(endpoint);
            boost::beast::ssl_stream<tcp::socket&> stream{s, ssl_ctx};
            stream.handshake(boost::asio::ssl:: stream_base::server);
            std::cout << "Принято новое подключение №" << ++connection_count << " от "
                      << endpoint << '\n';

            boost::beast::flat_buffer buffer;

            for(;;)
            {
                request_t req;
                boost::beast::http::read(stream, buffer, req);
                std::cout << req << '\n';

                auto res = generate_response(req);

                boost::beast::http::write(stream, res);

                if(!res.keep_alive())
                    break;
            }
            stream.shutdown();
        }
        catch (boost::system::system_error const& e)
        {
            std::cerr << "Поймано исключение " << e.what() << std::endl;
        }
    }
}

tcp::socket server::accept(tcp::endpoint& endpoint)
{
    worker_thread_manager::accepting_thread_guard guard(manager);
    return acceptor.accept(endpoint);
}

int main(int argc, char* argv[])
{
    try
    {
        int port = 1025;
        int max_idle_threads = 5;

        std::string certificate_file_name = "cert.pem";
        std::string private_key_file_name = "key.pem";
        std::string dh_params_file_name   = "dh.pem";
        std::string slack_params_token   = "token.txt";

        std::string username;


        for(int i = 1;;)
        {
            if(i == argc)
                break;
            std::string key = argv[i];
            ++i;
            if(i == argc)
                throw std::runtime_error("Ожидалось значение");
            std::string value = argv[i];
            ++i;
            if(key == "--port")
                port = stoi(value);
            else if (key == "--max-idle-threads")
                max_idle_threads = stoi(value);
            else if(key == "--certificate")
                certificate_file_name = value;
            else if(key == "--private-key")
                private_key_file_name = value;
            else if(key == "--dh-params")
                dh_params_file_name = value;
            else if(key == "--token")
                slack_params_token = value;
            else if(key == "--user")
                username = value;
            else
                throw std::runtime_error("Неизвестный параметр");

        }

        signal_set set = {SIGINT, SIGTERM, SIGHUP};
        block_signals block(set);
        boost::asio::io_context ctx;
        server_params params =
        {
            .endpoint         = tcp::endpoint (tcp::v4(), port),
            .max_idle_threads = static_cast<size_t>(max_idle_threads),
            .certificate      = read_file(certificate_file_name),
            .private_key      = read_file(private_key_file_name),
            .dh_params        = read_file(dh_params_file_name),
            .token            = read_file(slack_params_token)
        };

        if(!username.empty())
            change_user(username);

        server server(ctx, params);
        int sig_num = set.wait();
        std::cerr << "Завершаемся с сигналом " << sig_num << std::endl;
    }
    catch (std::exception const& e)
    {
        std::cout << e.what() << std::endl;
    }
}
