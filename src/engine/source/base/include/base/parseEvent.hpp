
#ifndef _PARSE_EVENT_H
#define _PARSE_EVENT_H

#include <string>

#include <base/baseTypes.hpp>

namespace base::parseEvent
{
constexpr char EVENT_QUEUE_ID[] {"/cyb3rhq/queue"};
constexpr char EVENT_LOCATION_ID[] {"/cyb3rhq/location"};
constexpr char EVENT_MESSAGE_ID[] {"/event/original"};

/**
 * @brief Parse an Cyb3rhq message and extract the queue, location and message
 *
 * @param event Cyb3rhq message
 * @return Event Event object
 */
Event parseCyb3rhqEvent(const std::string& event);

} // namespace base::parseEvent

#endif // _EVENT_UTILS_H
