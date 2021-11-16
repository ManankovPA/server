#ifndef SUPPRESS_CANCELLATION_H
#define SUPPRESS_CANCELLATION_H
#include <pthread.h>

struct suppress_cancellation
{
    suppress_cancellation()
    {
       pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
    }

    suppress_cancellation(suppress_cancellation const&) = delete;
    suppress_cancellation& operator=(suppress_cancellation const&) = delete;

    ~suppress_cancellation()
    {
       pthread_setcancelstate(oldstate, nullptr);
    }

private:
    int oldstate;
};

#endif // SUPPRESS_CANCELLATION_H
