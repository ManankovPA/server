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

struct server
{
    typedef boost::beast::http::response<boost::beast::http::string_body> response_t;
    typedef boost::beast::http::request<boost::beast::http::string_body> request_t;

    server(boost::asio::io_context& ctx, tcp::endpoint endpoint)
        :acceptor(ctx, endpoint)
        ,connection_count(0)
        ,ssl_ctx(boost::asio::ssl::context::tlsv12)
        ,manager(5, [this]{thread_proc(); })
    {
        load_server_certificate(ssl_ctx);
        manager.start();
    }

    void thread_proc();

    tcp::socket accept(tcp::endpoint& endpoint);

    response_t generate_response(request_t const & req);
    response_t generate_bad_request_response(request_t const& req, std::string const& str);

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

int main()
{
    try
    {
        signal_set set = {SIGINT, SIGTERM, SIGHUP};
        block_signals block(set);
        boost::asio::io_context ctx;
        server server(ctx, tcp::endpoint (tcp::v4(), 1025));
        int sig_num = set.wait();
        std::cerr << "Завершаемся с сигналом " << sig_num << std::endl;
    }
    catch (std::exception const& e)
    {
        std::cout << e.what() << std::endl;
    }


}
