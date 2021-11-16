#pragma once
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <map>
#include <thread>
#include <vector>
#include "suppress_cancellation.h"

struct worker_thread_manager
{
    worker_thread_manager(size_t max_accepting_threads, std::function<void ()> thread_proc);
    worker_thread_manager(worker_thread_manager const& other) = delete;
    worker_thread_manager& operator=(worker_thread_manager const& other) = delete;
    ~worker_thread_manager();

    void start();

    struct accepting_thread_guard
    {
        explicit accepting_thread_guard(worker_thread_manager& manager);
        accepting_thread_guard(accepting_thread_guard const& other) = delete;
        accepting_thread_guard& operator=(accepting_thread_guard const& other) = delete;
        ~accepting_thread_guard();

    private:
        worker_thread_manager& manager;
    };

private:
    struct thread_proc_guard
    {
        explicit thread_proc_guard(worker_thread_manager& manager);
        thread_proc_guard(thread_proc_guard const& other) = delete;
        thread_proc_guard& operator=(thread_proc_guard const& other) = delete;
        ~thread_proc_guard();

    private:
        worker_thread_manager& manager;
    };

    void add_thread();
    void manager_thread_proc();

private:
    size_t const max_accepting_threads;
    std::function<void ()> const thread_proc;

    std::atomic<size_t> now_accepting_threads;
    std::mutex m;
    std::condition_variable manager_cv;
    std::vector<std::thread::id> threads_to_join;
    std::map<std::thread::id, std::thread> threads;
    std::thread manager;
};

inline worker_thread_manager::worker_thread_manager(size_t max_accepting_threads, std::function<void()> thread_proc)
    : max_accepting_threads(max_accepting_threads)
    , thread_proc(std::move(thread_proc))
    , now_accepting_threads(0)
    , manager ([this]{manager_thread_proc();})
{}

inline worker_thread_manager::~worker_thread_manager()
{
    pthread_cancel(manager.native_handle());
    for (auto& p : threads)
        pthread_cancel(p.second.native_handle());

    manager_cv.notify_one();

    manager.join();
    for (auto& p : threads)
        p.second.join();

    assert(now_accepting_threads == 0);
    for (std::thread::id id : threads_to_join)
    {
        size_t n = threads.erase(id);
        assert(n == 1);
    }

    assert(threads.empty());
}

inline void worker_thread_manager::start()
{
    manager_cv.notify_one();
}

inline worker_thread_manager::accepting_thread_guard::accepting_thread_guard(worker_thread_manager& manager)
    : manager(manager)
{
    size_t old = manager.now_accepting_threads;

    do
    {
        if (old == manager.max_accepting_threads)
            pthread_cancel(pthread_self());
    }
    while(!manager.now_accepting_threads.compare_exchange_weak(old, old + 1));
}

inline worker_thread_manager::accepting_thread_guard::~accepting_thread_guard()
{
    if(--manager.now_accepting_threads == 0)
        manager.manager_cv.notify_one();
}

inline worker_thread_manager::thread_proc_guard::thread_proc_guard(worker_thread_manager& manager)
    : manager(manager)
{}

inline worker_thread_manager::thread_proc_guard::~thread_proc_guard()
{
    {
        std::lock_guard<std::mutex> lock(manager.m);
        manager.threads_to_join.push_back(std::this_thread::get_id());
    }
    manager.manager_cv.notify_one();
}

inline void worker_thread_manager::add_thread()
{
    threads_to_join.reserve(threads.size() + 1);

    std::thread new_thread([this]
    {
        thread_proc_guard pg(*this);
        thread_proc();
    });
    std::thread::id id = new_thread.get_id();

    threads.insert({id, std::move(new_thread)});
}

inline void worker_thread_manager::manager_thread_proc()
{
    for (;;)
    {
        std::unique_lock<std::mutex> lock(m);

        {
            suppress_cancellation sc;

            manager_cv.wait(lock, [this]
            {
                return !threads_to_join.empty() || now_accepting_threads == 0;
            });
        }

        pthread_testcancel();

        try
        {
            if (!threads_to_join.empty())
            {
                for (std::thread::id id : threads_to_join)
                {
                    auto it = threads.find(id);
                    assert(it != threads.end());
                    it->second.join();
                    threads.erase(it);
                }
                threads_to_join.clear();
            }

            if (now_accepting_threads == 0)
            {
                try
                {
                    add_thread();
                }
                catch (std::exception const& e)
                {
                    std::cerr << "Ошибка при создании потока " << e.what() << std::endl;
                }
            }
        }
        catch (...)
        {
            std::abort();
        }
    }
}
