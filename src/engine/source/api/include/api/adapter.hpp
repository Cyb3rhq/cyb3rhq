#ifndef _API_ADAPTER_HPP
#define _API_ADAPTER_HPP

#include <type_traits>
#include <variant>

#include <eMessages/eMessage.h>
#include <eMessages/engine.pb.h>
#include <base/utils/cyb3rhqProtocol/cyb3rhqRequest.hpp>
#include <base/utils/cyb3rhqProtocol/cyb3rhqResponse.hpp>

namespace api::adapter
{

/**
 * @brief Return a Cyb3rhqResponse with de eMessage serialized or a Cyb3rhqResponse with the error if it fails
 * @tparam T
 * @param eMessage
 * @return base::utils::cyb3rhqProtocol::Cyb3rhqResponse
 */
template<typename T>
base::utils::cyb3rhqProtocol::Cyb3rhqResponse toCyb3rhqResponse(const T& eMessage)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    const auto res = eMessage::eMessageToJson<T>(eMessage);

    if (std::holds_alternative<base::Error>(res))
    {
        const auto& error = std::get<base::Error>(res);
        return base::utils::cyb3rhqProtocol::Cyb3rhqResponse::internalError(error.message);
    }
    return base::utils::cyb3rhqProtocol::Cyb3rhqResponse {json::Json {std::get<std::string>(res).c_str()}};
}

/**
 * @brief Return a variant with the parsed eMessage or a Cyb3rhqResponse with the error
 *
 * @tparam T Request type
 * @tparam U Response type
 * @param json
 * @return std::variant<base::utils::cyb3rhqProtocol::Cyb3rhqResponse, T>
 */
template<typename T, typename U>
std::variant<base::utils::cyb3rhqProtocol::Cyb3rhqResponse, T>
fromCyb3rhqRequest(const base::utils::cyb3rhqProtocol::Cyb3rhqRequest& wRequest)
{
    // Check that T and U are derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_base_of<google::protobuf::Message, U>::value, "U must be a derived class of proto::Message");
    // Check that U has set_status and set_error functions
    static_assert(std::is_invocable_v<decltype(&U::set_status), U,::com::cyb3rhq::api::engine::ReturnStatus>,
                  "U must have set_status function");
    //static_assert(std::is_invocable_v<decltype(&U::set_error), U, const std::string&>,
    //              "U must have set_error function");

    const auto json = wRequest.getParameters().value_or(json::Json {"{}"}).str();

    auto res = eMessage::eMessageFromJson<T>(json);
    if (std::holds_alternative<base::Error>(res))
    {
        U eResponse;
        eResponse.set_status(::com::cyb3rhq::api::engine::ReturnStatus::ERROR);
        eResponse.set_error(std::get<base::Error>(res).message);
        return toCyb3rhqResponse<U>(eResponse);
    }

    return std::move(std::get<T>(res));
}

/**
 * @brief Return a Cyb3rhqResponse with the genericError in Cyb3rhqResponse
 *
 * @tparam T Response type
 * @param std::string Error message
 * @return std::variant<base::utils::cyb3rhqProtocol::Cyb3rhqResponse, T>
 */
template<typename T>
base::utils::cyb3rhqProtocol::Cyb3rhqResponse genericError(const std::string& message)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_invocable_v<decltype(&T::set_status), T, ::com::cyb3rhq::api::engine::ReturnStatus>,
                  "T must have set_status function");

    T eResponse;
    eResponse.set_status(::com::cyb3rhq::api::engine::ReturnStatus::ERROR);
    eResponse.set_error(message.data());
    return toCyb3rhqResponse<T>(eResponse);
}


/**
 * @brief Return a Cyb3rhqResponse with the status OK in Cyb3rhqResponse
 *
 * @tparam T Response type
 * @return std::variant<base::utils::cyb3rhqProtocol::Cyb3rhqResponse, T>
 */
template<typename T>
base::utils::cyb3rhqProtocol::Cyb3rhqResponse genericSuccess()
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_invocable_v<decltype(&T::set_status), T, ::com::cyb3rhq::api::engine::ReturnStatus>,
                  "T must have set_status function");

    T eResponse;
    eResponse.set_status(::com::cyb3rhq::api::engine::ReturnStatus::OK);
    return toCyb3rhqResponse<T>(eResponse);
}

} // namespace api::adapter

#endif // _API_ADAPTER_HPP
