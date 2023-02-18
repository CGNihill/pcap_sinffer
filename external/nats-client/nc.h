#pragma once

#include <nats.h>

class nats_client
{
private:
    // static constexpr char const *subject = "sniff.base";
    natsConnection *con = NULL;
    natsSubscription *sub = NULL;
    natsMsg *msg = NULL;

public:
    ~nats_client();

    // Connect client to nats-server by default url
    void nats_client_connect();

    // subscribe clien to some subscription
    void nats_client_subscribe(const char const *subject);

    // send binary data to client
    void nats_send_data(const void *data, int len, const char const *subject);

    // Only for database [Handler function for natsConnection_Subscribe -> onMsg]
    inline static std::function<void(const char *, int)> Hfunc;
};