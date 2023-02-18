#pragma once

#include <clickhouse/client.h>
#include <vector>
#include <map>
#include <utility>

class database
{
private:
    clickhouse::ClientOptions cl_options;
    clickhouse::Client client;

    std::map<std::string, std::vector<std::pair<std::string, clickhouse::Column *>>> columns;

    void parse_query(std::string q, const std::string table_name);

    template <class... T, class V>
    void append_data(std::vector<std::pair<std::string, clickhouse::Column *>> *table, int iterator, V value);
    template <class... T, class V>
    void append_data(std::vector<std::pair<std::string, clickhouse::Column *>> *table, int iterator, V value, T... args);

public:
    /**
     * Supported types (Int8/16/32/64/128, UInt8/16/32/64, Float32/64, String, UUID, Date/32, DateTime, IPv4/6)
     * filling occurs according to the list
     */
    database(const std::string user, const std::string password, const std::string host, const int port, const std::string database_name, const std::string table_name, const std::string table_struct_querry, const std::string engine);
    database(const std::string user, const std::string password, const std::string host, const int port, const std::string database_name);

    /**
     * Supported types (Int8/16/32/64/128, UInt8/16/32/64, Float32/64, String, UUID, Date/32, DateTime, IPv4/6)
     * filling occurs according to the list
     */
    void add_table(const std::string table_name, const std::string table_struct_querry, const std::string engine);

    /**
     * append by list from query
     */
    template <class... T>
    void append(const std::string table_name, T... args);

    void insert(const std::string table_name);

    ~database();
};