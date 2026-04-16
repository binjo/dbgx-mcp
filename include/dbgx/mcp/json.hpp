#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace dbgx::json {

using FieldMap = std::unordered_map<std::string, std::string>;

bool ParseObjectFields(std::string_view json_text, FieldMap* out_fields, std::string* error_message);
bool TryGetStringField(const FieldMap& fields, const std::string& key, std::string* out_value);
bool TryGetIntField(const FieldMap& fields, const std::string& key, int* out_value);
bool TryGetObjectField(
    const FieldMap& fields,
    const std::string& key,
    FieldMap* out_fields,
    std::string* error_message);
bool TryGetRawField(const FieldMap& fields, const std::string& key, std::string* out_raw_value);

std::string Escape(std::string_view text);
std::string Trim(std::string_view value);
bool IsNull(std::string_view value);

}  // namespace dbgx::json
