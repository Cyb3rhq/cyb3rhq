#include <gtest/gtest.h>

#include <base/utils/cyb3rhqProtocol/cyb3rhqRequest.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>

class Cyb3rhqRequest_validate : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class Cyb3rhqRequest_getCommand : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class Cyb3rhqRequest_getParameters : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class Cyb3rhqRequest_create : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class Cyb3rhqResponse : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

// A valid request
const json::Json jrequest {R"({
        "version": 1,
        "origin": {
            "name": "cyb3rhq-db",
            "module": "wdb"
        },
        "command": "test command",
        "parameters": {
            "param 1": "disconnected",
            "param 2": false,
            "param 3": 1,
            "param 4": 1.1
        }
        })"};

TEST_F(Cyb3rhqRequest_validate, validRequest)
{
    base::utils::cyb3rhqProtocol::Cyb3rhqRequest wrequest {jrequest};
    EXPECT_FALSE(wrequest.error());
    ASSERT_TRUE(wrequest.isValid());
}

TEST_F(Cyb3rhqRequest_validate, invalidVersion)
{
    // Invalid Value
    auto oldVersion {2};
    json::Json jrequest_invalid {jrequest};
    jrequest_invalid.setInt(oldVersion, "/version");
    base::utils::cyb3rhqProtocol::Cyb3rhqRequest wrequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 fmt::format("The request version ({}) is not supported, the supported version is {}",
                             oldVersion,
                             base::utils::cyb3rhqProtocol::Cyb3rhqRequest::SUPPORTED_VERSION)
                     .c_str());
    ASSERT_FALSE(wrequest.isValid());
}

TEST_F(Cyb3rhqRequest_validate, missingVersion)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/version");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have a 'version' field containing an integer value");
}

TEST_F(Cyb3rhqRequest_validate, wrongTypeVersion)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setString("1", "/version");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have a 'version' field containing an integer value");
}

TEST_F(Cyb3rhqRequest_validate, invalidCommandType)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setInt(1, "/command");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have a 'command' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, missingCommand)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/command");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have a 'command' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, invalidParametersType)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setString("{}", "/parameters");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 "The request must have a 'parameters' field containing a JSON object value");
}

TEST_F(Cyb3rhqRequest_validate, missingParameters)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/parameters");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 "The request must have a 'parameters' field containing a JSON object value");
}

TEST_F(Cyb3rhqRequest_validate, invalidOriginType)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setString("{}", "/origin");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have an 'origin' field containing a JSON object value");
}

TEST_F(Cyb3rhqRequest_validate, missingOrigin)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/origin");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have an 'origin' field containing a JSON object value");
}

TEST_F(Cyb3rhqRequest_validate, invalidOriginNameType)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setInt(1, "/origin/name");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have an 'origin/name' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, missingOriginName)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/origin/name");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have an 'origin/name' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, invalidOriginModuleType)
{
    // Wrong type
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setInt(1, "/origin/module");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 "The request must have an 'origin/module' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, missingOriginModule)
{
    // Missing field
    auto jrequest_invalid = jrequest;
    jrequest_invalid.erase("/origin/module");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 "The request must have an 'origin/module' field containing a string value");
}

TEST_F(Cyb3rhqRequest_validate, rootWrongType)
{
    // Wrong type
    auto jrequest_invalid = json::Json {R"("hi")"};
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must be a JSON object");
}

TEST_F(Cyb3rhqRequest_validate, rootWrongTypeArray)
{
    // Wrong type
    auto jrequest_invalid = json::Json {R"([123, "hi", 123])"};
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must be a JSON object");
}

TEST_F(Cyb3rhqRequest_getCommand, valid)
{
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest};
    ASSERT_TRUE(wrequest.isValid());
    ASSERT_STREQ(wrequest.getCommand().value().c_str(), "test command");
}

TEST_F(Cyb3rhqRequest_getParameters, valid)
{
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest};
    ASSERT_TRUE(wrequest.isValid());
    ASSERT_STREQ(wrequest.getParameters().value().str().c_str(),
                 R"({"param 1":"disconnected","param 2":false,"param 3":1,"param 4":1.1})");
}

TEST_F(Cyb3rhqRequest_getCommand, invalidRequest)
{
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setInt(123, "/command");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_FALSE(wrequest.getCommand());
    ASSERT_STREQ(wrequest.error()->c_str(), "The request must have a 'command' field containing a string value");
}

TEST_F(Cyb3rhqRequest_getParameters, invalidRequest)
{
    auto jrequest_invalid = jrequest;
    jrequest_invalid.setString("{}", "/parameters");
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest {jrequest_invalid};
    EXPECT_TRUE(wrequest.error());
    ASSERT_FALSE(wrequest.isValid());
    ASSERT_FALSE(wrequest.getParameters());
    ASSERT_STREQ(wrequest.error()->c_str(),
                 "The request must have a 'parameters' field containing a JSON object value");
}

TEST_F(Cyb3rhqRequest_create, valid_paramObjtype)
{
    auto wrequest = base::utils::cyb3rhqProtocol::Cyb3rhqRequest::create(
        "test command", "api", json::Json {R"({"param 1":"disconnected","param 2":false,"param 3":1,"param 4":1.1})"});
    ASSERT_TRUE(wrequest.isValid());
    ASSERT_STREQ(wrequest.getCommand().value().c_str(), "test command");
    ASSERT_STREQ(wrequest.getParameters().value().str().c_str(),
                 R"({"param 1":"disconnected","param 2":false,"param 3":1,"param 4":1.1})");
}

TEST_F(Cyb3rhqRequest_create, invalid_paramArraytype)
{
    ASSERT_THROW(base::utils::cyb3rhqProtocol::Cyb3rhqRequest::create(
                     "test command",
                     "api",
                     json::Json {R"(["param 1","disconnected","param 2",false,"param 3",1,"param 4",1.1])"}),
                 std::runtime_error);
}

TEST_F(Cyb3rhqRequest_create, invalid_emptyCommand)
{
    ASSERT_THROW(base::utils::cyb3rhqProtocol::Cyb3rhqRequest::create(
                     "", "api", json::Json {R"({"param 1":"disconnected","param 2":false,"param 3":1,"param 4":1.1})"}),
                 std::runtime_error);
}
