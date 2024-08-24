#ifndef _BASE_UTILS_CYB3RHQ_REQUEST_HPP
#define _BASE_UTILS_CYB3RHQ_REQUEST_HPP

#include <base/json.hpp>

namespace base::utils::cyb3rhqProtocol
{

/**
 * @brief A standard protocol for internal communication between Cyb3rhq components
 *
 * https://github.com/cyb3rhq/cyb3rhq/issues/5934
 */
class Cyb3rhqRequest
{
    int m_version;
    json::Json m_jrequest;
    std::optional<std::string> m_error;

public:
    static constexpr auto SUPPORTED_VERSION {1};

    Cyb3rhqRequest() = default;
    // TODO Delete explicit when json constructor does not throw exceptions
    /**
     * @brief Construct a new Cyb3rhq Request object
     *
     * @param json
     */
    explicit Cyb3rhqRequest(const json::Json& json)
    {
        m_jrequest = json::Json(json);
        m_version = -1;
        m_error = validate();
    }

    /**
     * @brief Destroy the Cyb3rhq Request object
     */
    ~Cyb3rhqRequest() = default;


    // copy constructor
    Cyb3rhqRequest(const Cyb3rhqRequest& other)
    {
        m_version = other.m_version;
        m_jrequest = json::Json {other.m_jrequest};
        m_error = other.m_error;
    }

    // move constructor
    Cyb3rhqRequest(Cyb3rhqRequest&& other) noexcept
    {
        m_version = other.m_version;
        m_jrequest = std::move(other.m_jrequest);
        m_error = std::move(other.m_error);
    }

    // copy assignment
    Cyb3rhqRequest& operator=(const Cyb3rhqRequest& other)
    {
        m_version = other.m_version;
        m_jrequest = json::Json {other.m_jrequest};
        m_error = other.m_error;
        return *this;
    }

    // move assignment
    Cyb3rhqRequest& operator=(Cyb3rhqRequest&& other) noexcept
    {
        m_version = other.m_version;
        m_jrequest = std::move(other.m_jrequest);
        m_error = std::move(other.m_error);
        return *this;
    }

    /**
     * @brief Get command from the request
     *
     * @return std::string command
     * @return empty if the request is not valid
     */
    std::optional<std::string> getCommand() const
    {
        return isValid() ? m_jrequest.getString("/command") : std::nullopt;
    };

    /**
     * @brief Get parameters from the request
     *
     * @return json::Json parameters
     * @return empty if the request is not valid
     */
    std::optional<json::Json> getParameters() const
    {
        return isValid() ? m_jrequest.getJson("/parameters") : std::nullopt;
    }

    /**
     * @brief Check if the request is valid
     *
     * @return true if the request is valid
     * @return false if the request is not valid
     */
    bool isValid() const { return !m_error.has_value(); }

    /**
     * @brief Get the error message
     *
     * @return empty if the request is valid
     * @return std::optional<std::string> error message
     */
    std::optional<std::string> error() const { return m_error; }

    /**
     * @brief Create a Cyb3rhq Request object from a command and parameters
     *
     * @param command Command name
     * @param parameters Parameters
     * @return Cyb3rhqRequest
     *
     * @throw std::runtime_error if the command is empty or the parameters are not a JSON
     * object
     */
    static Cyb3rhqRequest create(std::string_view command, std::string_view originName, const json::Json& parameters);

    std::string toStr() const { return m_jrequest.str(); }

private:
    /**
     * @brief Validate the cyb3rhq request protocol
     *
     * @return std::optional<std::string> Error message if the request is not valid
     * @return nullopt if the request is valid
     */
    std::optional<std::string> validate() const;
};

} // namespace base::utils::cyb3rhqProtocol

#endif // _API_CYB3RHQ_REQUEST_HPP
