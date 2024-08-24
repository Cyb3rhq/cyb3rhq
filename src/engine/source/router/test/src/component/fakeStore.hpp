#ifndef _COMPONENT_FAKE_STORE_HPP
#define _COMPONENT_FAKE_STORE_HPP

constexpr auto ROUTER_JSON {R"([])"};

constexpr auto TESTER_JSON {R"([])"};

constexpr auto POLICY_JSON {
    R"({"name":"policy/cyb3rhq/0","hash":"12403460954181119054","assets":["integration/cyb3rhq-core-fake/0"]})"};

constexpr auto FILTER_JSON {R"({
    "name": "filter/allow-all/0"
})"};

constexpr auto EPS_JSON {
    R"({
    "eps": 1,
    "refreshInterval": 1,
    "active": false
})"};

constexpr auto INTEGRATION_JSON {R"({
"name": "integration/cyb3rhq-core-fake/0",
"decoders": ["decoder/fake/0"]}
)"};

auto constexpr DECODER_JSON = R"e({
    "name": "decoder/fake/0",
    "normalize": [
        {
        "map": [
            {
            "cyb3rhq.message": "I am an fake decoder"
            }
        ]
        }
    ]
    })e";

auto constexpr CYB3RHQ_LOGPAR_TYPES_JSON = R"({
    "fields": {
        "cyb3rhq.message": "text"
    }
}
)";

#endif // _COMPONENT_FAKE_STORE_HPP
