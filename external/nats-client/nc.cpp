#include "nc.h"

#include <iostream>
#include <functional>
#include <exception>
#include <nats/nats.h>

nats_client::~nats_client()
{
    natsSubscription_Destroy(sub);
    natsConnection_Close(con);
    natsConnection_Destroy(con);
}

void nats_client::nats_client_connect()
{
    natsConnection_ConnectTo(&con, NATS_DEFAULT_URL);
}

// handler function for natsConnection_Subscribe(...) [call another handler function<void(const char*, int)> (for database)]
void onMsg(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure)
{
    nats_client::Hfunc(natsMsg_GetData(msg), natsMsg_GetDataLength(msg));
    natsMsg_Destroy(msg);
}

void nats_client::nats_client_subscribe(const char const *subject)
{
    natsConnection_Subscribe(&sub, con, subject, onMsg, NULL);
}

void nats_client::nats_send_data(const void *data, int len, const char const *subject)
{
    if (natsConnection_Publish(con, subject, data, len) == NATS_ERR)
    {
        throw std::runtime_error("nats send error");
    }
}