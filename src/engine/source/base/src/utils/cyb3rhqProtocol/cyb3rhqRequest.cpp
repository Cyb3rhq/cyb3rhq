#include "utils/cyb3rhqProtocol/cyb3rhqRequest.hpp"

#include <base/logging.hpp>

namespace base::utils::cyb3rhqProtocol
{
/*
 * https://github.com/cyb3rhq/cyb3rhq/issues/5934
 */
std::optional<std::string> Cyb3rhqRequest::validate() const
{
    if (!m_jrequest.isObject())
    {
        return "The request must be a JSON object";
    }
    if (!m_jrequest.exists("/version") || !m_jrequest.isInt("/version"))
    {
        return "The request must have a 'version' field containing an integer value";
    }
    // Check if the version is supported
    if (m_jrequest.getInt("/version").value() != SUPPORTED_VERSION)
    {
        return fmt::format("The request version ({}) is not supported, the supported version is {}",
                           m_jrequest.getInt("/version").value(),
                           SUPPORTED_VERSION);
    }
    if (!m_jrequest.isString("/command"))
    {
        return "The request must have a 'command' field containing a string value";
    }
    if (!m_jrequest.isObject("/parameters"))
    {
        return "The request must have a 'parameters' field containing a JSON object value";
    }
    if (!m_jrequest.isObject("/origin"))
    {
        return "The request must have an 'origin' field containing a JSON object value";
    }
    if (!m_jrequest.isString("/origin/name"))
    {
        return "The request must have an 'origin/name' field containing a string value";
    }
    if (!m_jrequest.isString("/origin/module"))
    {
        return "The request must have an 'origin/module' field containing a string value";
    }

    return std::nullopt;
}

Cyb3rhqRequest Cyb3rhqRequest::create(std::string_view command, std::string_view originName, const json::Json& parameters)
{

    if (command.empty())
    {
        LOG_DEBUG("Engine API request: '{}' method: command: '{}', origin name: '{}', parameters: '{}'.",
                  __func__,
                  command,
                  originName,
                  parameters.str());

        throw std::runtime_error("The command cannot be empty");
    }
    if (!parameters.isObject())
    {
        LOG_DEBUG("Engine API request: '{}' method: command: '{}', origin name: '{}', parameters: '{}'.",
                  __func__,
                  command,
                  originName,
                  parameters.str());

        throw std::runtime_error("The command parameters must be a JSON object");
    }

    json::Json jrequest;
    jrequest.setInt(SUPPORTED_VERSION, "/version");
    jrequest.setString(command, "/command");
    jrequest.set("/parameters", parameters);
    jrequest.setString("cyb3rhq-engine", "/origin/module");
    jrequest.setString(originName, "/origin/name");

    return Cyb3rhqRequest(jrequest);
}

} // namespace base::utils::cyb3rhqProtocol
