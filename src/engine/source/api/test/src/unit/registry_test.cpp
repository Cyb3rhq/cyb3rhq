
#include <gtest/gtest.h>

#include <api/api.hpp>
#include <api/registry.hpp>
#include <base/utils/cyb3rhqProtocol/cyb3rhqProtocol.hpp>

using namespace base::utils::cyb3rhqProtocol;

TEST(Registry, exec)
{

    // Registry
    api::Registry registry;

    // Get callback in registry
    auto cmdTest = registry.getHandler("test");

    auto res = std::make_shared<std::string>();

    auto callbackFn = [&res](const Cyb3rhqResponse& response)
    {
        *res = response.toString();
    };

    // Execute 2 times the callback fn
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

}

TEST(Registry, addComand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);

    auto res = std::make_shared<std::string>();

    auto callbackFn = [&res](const Cyb3rhqResponse& response)
    {
        *res = response.toString();
    };

    cmdTest(Cyb3rhqRequest::create(command, "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");
    auto cmdNotFound = *res;

    // Add command
    registry.registerHandler(command, api::Api::convertToHandlerAsync(
                             [](Cyb3rhqRequest) -> Cyb3rhqResponse
                             { return Cyb3rhqResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 0, "OK"); }));

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{"testArgKey":"testArgValue"},"error":0,"message":"OK"})");

    // Check the new command against the old one
    ASSERT_NE(cmdNotFound, *res);
}

TEST(Registry, addNullCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    auto res = std::make_shared<std::string>();

    auto callbackFn = [&res](const Cyb3rhqResponse& response)
    {
        *res = response.toString();
    };

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    auto cmdNotFound = *res;
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command
    bool resp = registry.registerHandler(command, nullptr);
    ASSERT_FALSE(resp); // Fail

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    // Check the new command against the old one
    ASSERT_EQ(cmdNotFound, *res);
}

TEST(Registry, AddDuplicateCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    auto res = std::make_shared<std::string>();

    auto callbackFn = [&res](const Cyb3rhqResponse& response)
    {
        *res = response.toString();
    };

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool resp = registry.registerHandler(
        command, api::Api::convertToHandlerAsync(
        [](Cyb3rhqRequest) -> Cyb3rhqResponse
        { return Cyb3rhqResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd1"); }));

    ASSERT_TRUE(resp); // OK
    // Get callback in registry
    cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Add command
    resp = registry.registerHandler(
        command, api::Api::convertToHandlerAsync(
        [](Cyb3rhqRequest) -> Cyb3rhqResponse
        { return Cyb3rhqResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd2"); }));

    ASSERT_FALSE(resp); // Fail

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");
}

TEST(Registry, AddMultipleCommands)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};
    std::string command2 {"test2"};

    auto res = std::make_shared<std::string>();

    auto callbackFn = [&res](const Cyb3rhqResponse& response)
    {
        *res = response.toString();
    };

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool resp = registry.registerHandler(
        command, api::Api::convertToHandlerAsync(
        [](Cyb3rhqRequest) -> Cyb3rhqResponse
        { return Cyb3rhqResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd1"); }));

    ASSERT_TRUE(resp); // OK

    // Add command for the first time
    resp = registry.registerHandler(
        command2, api::Api::convertToHandlerAsync(
        [](Cyb3rhqRequest) -> Cyb3rhqResponse
        { return Cyb3rhqResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 2, "OK cmd2"); }));

    ASSERT_TRUE(resp); // OK

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Get callback in registry
    cmdTest = registry.getHandler(command2);
    cmdTest(Cyb3rhqRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}), callbackFn);
    ASSERT_EQ(*res, R"({"data":{"testArgKey":"testArgValue"},"error":2,"message":"OK cmd2"})");
}
