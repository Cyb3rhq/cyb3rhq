#include <gtest/gtest.h>

#include <base/utils/cyb3rhqProtocol/cyb3rhqResponse.hpp>

TEST(Cyb3rhqResponse, constructor)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.data(), jdata);
    EXPECT_EQ(wresponse.error(), error);
    EXPECT_EQ(wresponse.message(), message);
}

TEST(Cyb3rhqResponse, toString)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0,"message":"test message"})");
}

TEST(Cyb3rhqResponse, toStringNoMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0})");
}

TEST(Cyb3rhqResponse, toStringEmptyMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {""};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0})");
}

TEST(Cyb3rhqResponse, toStringEmptyData)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{},"error":0,"message":"test message"})");
}

TEST(Cyb3rhqResponse, toStringArrayData)
{
    const json::Json jdata {R"([{"test": "data"}])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":[{"test":"data"}],"error":0,"message":"test message"})");
}

TEST(Cyb3rhqResponse, toStringEmptyDataEmptyMessage)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {""};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{},"error":0})");
}

TEST(Cyb3rhqResponse, validateOkObject)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkArray)
{
    const json::Json jdata {R"([{"test": "data"}])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkEmptyObject)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkEmptyArray)
{
    const json::Json jdata {R"([])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkEmptyMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {""};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkEmptyData)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateOkEmptyDataEmptyMessage)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {""};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateErrorInvalidDataStr)
{
    const json::Json jdata {R"("test")"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateErrorInvalidDataInt)
{
    const json::Json jdata {R"(1)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateErrorInvalidDataBool)
{
    const json::Json jdata {R"(true)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(Cyb3rhqResponse, validateErrorInvalidDataNull)
{
    const json::Json jdata {R"(null)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::cyb3rhqProtocol::Cyb3rhqResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}
