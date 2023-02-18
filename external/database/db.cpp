#include "db.h"

#include <clickhouse/client.h>

#include <sstream>
#include <exception>
#include <utility>

database::~database()
{
    for (auto [table_name, col] : columns)
    {
        for (int i = 0; i < col.size(); i++)
        {
            delete col[i].second;
        }
    }
}

void database::parse_query(std::string q, const std::string table_name)
{
    std::istringstream query_stream(q);
    std::string token;
    while (std::getline(query_stream, token, ','))
    {
        if (token.length() <= 0)
            continue;
        std::istringstream tab(token);
        std::string t, name = "";
        while (std::getline(tab, t, ' '))
        {
            if (t.length() <= 0)
                continue;

            std::pair<std::string, clickhouse::Column *> p;
            p.first = name;
            if (t == "Int8")
                p.second = new clickhouse::ColumnInt8();
            else if (t == "Int16")
                p.second = new clickhouse::ColumnInt16();
            else if (t == "Int32")
                p.second = new clickhouse::ColumnInt32();
            else if (t == "Int64")
                p.second = new clickhouse::ColumnInt64();
            else if (t == "Int128")
                p.second = new clickhouse::ColumnInt128();
            else if (t == "UInt8")
                p.second = new clickhouse::ColumnUInt8();
            else if (t == "UInt16")
                p.second = new clickhouse::ColumnUInt16();
            else if (t == "UInt32")
                p.second = new clickhouse::ColumnUInt32();
            else if (t == "UInt64")
                p.second = new clickhouse::ColumnUInt64();
            else if (t == "Float32")
                p.second = new clickhouse::ColumnFloat32();
            else if (t == "Float64")
                p.second = new clickhouse::ColumnFloat64();
            else if (t == "String")
                p.second = new clickhouse::ColumnString();
            else if (t == "UUID")
                p.second = new clickhouse::ColumnUUID();
            else if (t == "Date")
                p.second = new clickhouse::ColumnDate();
            else if (t == "Date32")
                p.second = new clickhouse::ColumnDate32();
            else if (t == "DateTime")
                p.second = new clickhouse::ColumnDateTime();
            else if (t == "IPv4")
                p.second = new clickhouse::ColumnIPv4();
            else if (t == "IPv6")
                p.second = new clickhouse::ColumnIPv6();
            else
                name = t;

            if (t == "Int8" || t == "Int16" || t == "Int32" || t == "Int64" || t == "Int128" || t == "UInt8" || t == "UInt16" || t == "UInt32" || t == "UInt64" || t == "Float32" || t == "Float64" || t == "String" || t == "UUID" || t == "Date" || t == "Date32" || t == "DateTime" || t == "IPv4" || t == "IPv6")
                columns[table_name].push_back(p);
        }
    }
}

database::database(const std::string user, const std::string password, const std::string host, const int port, const std::string database_name, const std::string table_name, const std::string table_struct_querry, const std::string engine)
    : cl_options(clickhouse::ClientOptions().SetUser(user).SetPassword(password).SetPort(port).SetHost(host).SetDefaultDatabase(database_name)),
      client(cl_options)
{
    this->add_table(table_name, table_struct_querry, engine);
}

database::database(const std::string user, const std::string password, const std::string host, const int port, const std::string database_name)
    : cl_options(clickhouse::ClientOptions().SetUser(user).SetPassword(password).SetPort(port).SetHost(host).SetDefaultDatabase(database_name)),
      client(cl_options) {}

void database::add_table(const std::string table_name, const std::string table_struct_querry, const std::string engine)
{
    client.Execute("CREATE TABLE IF NOT EXISTS " + cl_options.default_database + "." + table_name + " (" + table_struct_querry + ") ENGINE = " + engine);
    parse_query(table_struct_querry, table_name);
}

template <class... T, class V>
void database::append_data(std::vector<std::pair<std::string, clickhouse::Column *>> *table, int iterator, V value) { (*table)[iterator].second.Append(value); }

template <class... T, class V>
void database::append_data(std::vector<std::pair<std::string, clickhouse::Column *>> *table, int iterator, V value, T... args)
{
    (*table)[iterator].second->Append(value);
    this->append_data(table, (iterator + 1), args...);
}

template <class... T>
void database::append(const std::string table_name, T... args)
{
    this->append_data(&(columns[table_name]), 0, args...);
}

void database::insert(const std::string table_name)
{
    clickhouse::Block block;
    for (int i = 0; i < this->columns[table_name].size(); i++)
    {
        block.AppendColumn(this->columns[table_name][i].first, std::make_shared<clickhouse::Column>(this->columns[table_name][i].second));
    }

    client.Insert(table_name, block);

    for (int i = 0; i < this->columns[table_name].size(); i++)
    {
        this->columns[table_name][i].second->Clear();
    }
}