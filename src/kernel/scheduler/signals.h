#ifndef SIGNALS_H
#define SIGNALS_H

#define SIGCNT 1

#define SIGKILL 0

struct SigHandler {
    void *handler_address;
};

#endif // SIGNALS_H
