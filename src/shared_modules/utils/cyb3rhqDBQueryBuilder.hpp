/*
 * Cyb3rhq DB Query Builder
 * Copyright (C) 2015, Cyb3rhq Inc.
 * October 31, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CYB3RHQ_DB_QUERY_BUILDER_HPP
#define _CYB3RHQ_DB_QUERY_BUILDER_HPP

#include "builder.hpp"
#include "stringHelper.h"
#include <string>

constexpr auto CYB3RHQ_DB_ALLOWED_CHARS {"-_ "};

class Cyb3rhqDBQueryBuilder final : public Utils::Builder<Cyb3rhqDBQueryBuilder>
{
private:
    std::string m_query;

public:
    Cyb3rhqDBQueryBuilder& global()
    {
        m_query += "global sql ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& agent(const std::string& id)
    {
        if (!Utils::isNumber(id))
        {
            throw std::runtime_error("Invalid agent id");
        }

        m_query += "agent " + id + " sql ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& selectAll()
    {
        m_query += "SELECT * ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& fromTable(const std::string& table)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(table, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid table name");
        }
        m_query += "FROM " + table + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& whereColumn(const std::string& column)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(column, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid column name");
        }
        m_query += "WHERE " + column + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& isNull()
    {
        m_query += "IS NULL ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& isNotNull()
    {
        m_query += "IS NOT NULL ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& equalsTo(const std::string& value)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(value, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid value");
        }
        m_query += "= '" + value + "' ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& andColumn(const std::string& column)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(column, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid column name");
        }
        m_query += "AND " + column + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& orColumn(const std::string& column)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(column, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid column name");
        }
        m_query += "OR " + column + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& globalGetCommand(const std::string& command)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(command, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid command");
        }
        m_query += "global get-" + command + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& globalFindCommand(const std::string& command)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(command, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid command");
        }
        m_query += "global find-" + command + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& globalSelectCommand(const std::string& command)
    {
        if (!Utils::isAlphaNumericWithSpecialCharacters(command, CYB3RHQ_DB_ALLOWED_CHARS))
        {
            throw std::runtime_error("Invalid command");
        }
        m_query += "global select-" + command + " ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& agentGetOsInfoCommand(const std::string& id)
    {
        if (!Utils::isNumber(id))
        {
            throw std::runtime_error("Invalid agent id");
        }
        m_query += "agent " + id + " osinfo get ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& agentGetHotfixesCommand(const std::string& id)
    {
        if (!Utils::isNumber(id))
        {
            throw std::runtime_error("Invalid agent id");
        }
        m_query += "agent " + id + " hotfix get ";
        return *this;
    }

    Cyb3rhqDBQueryBuilder& agentGetPackagesCommand(const std::string& id)
    {
        if (!Utils::isNumber(id))
        {
            throw std::runtime_error("Invalid agent id");
        }
        m_query += "agent " + id + " package get ";
        return *this;
    }

    std::string build()
    {
        return m_query;
    }
};

#endif /* _CYB3RHQ_DB_QUERY_BUILDER_HPP */
