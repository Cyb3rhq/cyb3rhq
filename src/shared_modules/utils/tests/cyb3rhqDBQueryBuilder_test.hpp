/*
 * Cyb3rhq shared modules utils
 * Copyright (C) 2015, Cyb3rhq Inc.
 * Nov 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CYB3RHQ_DB_QUERY_BUILDER_TEST_HPP
#define _CYB3RHQ_DB_QUERY_BUILDER_TEST_HPP

#include "gtest/gtest.h"

class Cyb3rhqDBQueryBuilderTest : public ::testing::Test
{
protected:
    Cyb3rhqDBQueryBuilderTest() = default;
    virtual ~Cyb3rhqDBQueryBuilderTest() = default;

    void SetUp() override {};
    void TearDown() override {};
};

#endif // _CYB3RHQ_DB_QUERY_BUILDER_TEST_HPP
