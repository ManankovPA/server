#ifndef CPP_SIGNALS_H
#define CPP_SIGNALS_H

#include <signal.h>
#include <initializer_list>

struct signal_set
{
    signal_set()
    {
        sigemptyset(&set);
    }

    signal_set(std::initializer_list<int> signals)
        : signal_set()
    {
        for (int sig : signals)
            add(sig);
    }

    void add(int signum)
    {
        sigaddset(&set, signum);
    }

    int wait()
    {
        int sig;
        sigwait(&set, &sig);
        return sig;
    }

private:
    sigset_t set;

    friend struct block_signals;
};

struct block_signals
{
    explicit block_signals(signal_set mask)
    {
        pthread_sigmask(SIG_BLOCK, &mask.set, &old_mask);
    }

    block_signals(block_signals const&) = delete;
    block_signals& operator=(block_signals const&) = delete;

    ~block_signals()
    {
        pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    }

private:
    sigset_t old_mask;

};

#endif // CPP_SIGNALS_H
