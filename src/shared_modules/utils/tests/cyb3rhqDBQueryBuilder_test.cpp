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

#include "cyb3rhqDBQueryBuilder_test.hpp"
#include "cyb3rhqDBQueryBuilder.hpp"
#include <string>

TEST_F(Cyb3rhqDBQueryBuilderTest, GlobalTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().global().selectAll().fromTable("agent").build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, AgentTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().agent("0").selectAll().fromTable("sys_programs").build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, WhereTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, WhereAndTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .andColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' AND version = '1' ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, WhereOrTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .orColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' OR version = '1' ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, WhereIsNullTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .isNull()
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name IS NULL ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, WhereIsNotNullTest)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .isNotNull()
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name IS NOT NULL ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, InvalidValue)
{
    EXPECT_THROW(Cyb3rhqDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs")
                     .whereColumn("name")
                     .equalsTo("bash'")
                     .build(),
                 std::runtime_error);
}

TEST_F(Cyb3rhqDBQueryBuilderTest, InvalidColumn)
{
    EXPECT_THROW(Cyb3rhqDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs")
                     .whereColumn("name'")
                     .equalsTo("bash")
                     .build(),
                 std::runtime_error);
}

TEST_F(Cyb3rhqDBQueryBuilderTest, InvalidTable)
{
    EXPECT_THROW(Cyb3rhqDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs'")
                     .whereColumn("name")
                     .equalsTo("bash")
                     .build(),
                 std::runtime_error);
}

TEST_F(Cyb3rhqDBQueryBuilderTest, GlobalGetCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().globalGetCommand("agent-info 1").build();
    EXPECT_EQ(message, "global get-agent-info 1 ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, GlobalFindCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().globalFindCommand("agent 1").build();
    EXPECT_EQ(message, "global find-agent 1 ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, GlobalSelectCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().globalSelectCommand("agent-name 1").build();
    EXPECT_EQ(message, "global select-agent-name 1 ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, AgentGetOsInfoCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().agentGetOsInfoCommand("1").build();
    EXPECT_EQ(message, "agent 1 osinfo get ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, AgentGetHotfixesCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().agentGetHotfixesCommand("1").build();
    EXPECT_EQ(message, "agent 1 hotfix get ");
}

TEST_F(Cyb3rhqDBQueryBuilderTest, AgentGetPackagesCommand)
{
    std::string message = Cyb3rhqDBQueryBuilder::builder().agentGetPackagesCommand("1").build();
    EXPECT_EQ(message, "agent 1 package get ");
}
