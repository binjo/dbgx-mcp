#include "dbgx/mcp/json.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>

namespace dbgx::json {

namespace {

bool IsWhitespace(char ch) {
  return std::isspace(static_cast<unsigned char>(ch)) != 0;
}

void SkipWhitespace(std::string_view text, std::size_t* pos) {
  while (*pos < text.size() && IsWhitespace(text[*pos])) {
    ++(*pos);
  }
}

bool IsHexDigit(char ch) {
  return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

int HexDigitValue(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + ch - 'a';
  }
  return 10 + ch - 'A';
}

void AppendUtf8(std::uint32_t code_point, std::string* out) {
  if (code_point <= 0x7F) {
    out->push_back(static_cast<char>(code_point));
    return;
  }
  if (code_point <= 0x7FF) {
    out->push_back(static_cast<char>(0xC0 | ((code_point >> 6) & 0x1F)));
    out->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    return;
  }
  if (code_point <= 0xFFFF) {
    out->push_back(static_cast<char>(0xE0 | ((code_point >> 12) & 0x0F)));
    out->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    return;
  }
  out->push_back(static_cast<char>(0xF0 | ((code_point >> 18) & 0x07)));
  out->push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
  out->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
  out->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
}

bool ParseJsonString(
    std::string_view text,
    std::size_t* pos,
    std::string* out,
    std::string* error_message) {
  if (*pos >= text.size() || text[*pos] != '"') {
    if (error_message != nullptr) {
      *error_message = "Expected JSON string";
    }
    return false;
  }

  ++(*pos);
  out->clear();

  while (*pos < text.size()) {
    const char ch = text[*pos];
    ++(*pos);

    if (ch == '"') {
      return true;
    }

    if (ch == '\\') {
      if (*pos >= text.size()) {
        if (error_message != nullptr) {
          *error_message = "Unterminated escape sequence";
        }
        return false;
      }

      const char escaped = text[*pos];
      ++(*pos);
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          out->push_back(escaped);
          break;
        case 'b':
          out->push_back('\b');
          break;
        case 'f':
          out->push_back('\f');
          break;
        case 'n':
          out->push_back('\n');
          break;
        case 'r':
          out->push_back('\r');
          break;
        case 't':
          out->push_back('\t');
          break;
        case 'u': {
          if (*pos + 4 > text.size()) {
            if (error_message != nullptr) {
              *error_message = "Invalid unicode escape";
            }
            return false;
          }

          std::uint32_t value = 0;
          for (int i = 0; i < 4; ++i) {
            const char hex = text[*pos + i];
            if (!IsHexDigit(hex)) {
              if (error_message != nullptr) {
                *error_message = "Invalid unicode escape";
              }
              return false;
            }
            value = (value << 4) | static_cast<std::uint32_t>(HexDigitValue(hex));
          }
          *pos += 4;
          AppendUtf8(value, out);
          break;
        }
        default:
          if (error_message != nullptr) {
            *error_message = "Unsupported escape sequence";
          }
          return false;
      }
      continue;
    }

    if (static_cast<unsigned char>(ch) < 0x20) {
      if (error_message != nullptr) {
        *error_message = "Control character is not allowed in JSON string";
      }
      return false;
    }

    out->push_back(ch);
  }

  if (error_message != nullptr) {
    *error_message = "Unterminated JSON string";
  }
  return false;
}

bool SkipJsonValue(std::string_view text, std::size_t* pos, std::string* error_message);

bool SkipJsonObject(std::string_view text, std::size_t* pos, std::string* error_message) {
  if (*pos >= text.size() || text[*pos] != '{') {
    if (error_message != nullptr) {
      *error_message = "Expected object";
    }
    return false;
  }

  ++(*pos);
  SkipWhitespace(text, pos);

  if (*pos < text.size() && text[*pos] == '}') {
    ++(*pos);
    return true;
  }

  while (*pos < text.size()) {
    std::string key;
    if (!ParseJsonString(text, pos, &key, error_message)) {
      return false;
    }

    SkipWhitespace(text, pos);
    if (*pos >= text.size() || text[*pos] != ':') {
      if (error_message != nullptr) {
        *error_message = "Expected ':' after object key";
      }
      return false;
    }

    ++(*pos);
    SkipWhitespace(text, pos);

    if (!SkipJsonValue(text, pos, error_message)) {
      return false;
    }

    SkipWhitespace(text, pos);
    if (*pos >= text.size()) {
      if (error_message != nullptr) {
        *error_message = "Unterminated object";
      }
      return false;
    }

    if (text[*pos] == ',') {
      ++(*pos);
      SkipWhitespace(text, pos);
      continue;
    }

    if (text[*pos] == '}') {
      ++(*pos);
      return true;
    }

    if (error_message != nullptr) {
      *error_message = "Expected ',' or '}' in object";
    }
    return false;
  }

  if (error_message != nullptr) {
    *error_message = "Unterminated object";
  }
  return false;
}

bool SkipJsonArray(std::string_view text, std::size_t* pos, std::string* error_message) {
  if (*pos >= text.size() || text[*pos] != '[') {
    if (error_message != nullptr) {
      *error_message = "Expected array";
    }
    return false;
  }

  ++(*pos);
  SkipWhitespace(text, pos);

  if (*pos < text.size() && text[*pos] == ']') {
    ++(*pos);
    return true;
  }

  while (*pos < text.size()) {
    if (!SkipJsonValue(text, pos, error_message)) {
      return false;
    }

    SkipWhitespace(text, pos);
    if (*pos >= text.size()) {
      if (error_message != nullptr) {
        *error_message = "Unterminated array";
      }
      return false;
    }

    if (text[*pos] == ',') {
      ++(*pos);
      SkipWhitespace(text, pos);
      continue;
    }

    if (text[*pos] == ']') {
      ++(*pos);
      return true;
    }

    if (error_message != nullptr) {
      *error_message = "Expected ',' or ']' in array";
    }
    return false;
  }

  if (error_message != nullptr) {
    *error_message = "Unterminated array";
  }
  return false;
}

bool SkipJsonValue(std::string_view text, std::size_t* pos, std::string* error_message) {
  SkipWhitespace(text, pos);
  if (*pos >= text.size()) {
    if (error_message != nullptr) {
      *error_message = "Expected JSON value";
    }
    return false;
  }

  const char ch = text[*pos];
  if (ch == '{') {
    return SkipJsonObject(text, pos, error_message);
  }
  if (ch == '[') {
    return SkipJsonArray(text, pos, error_message);
  }
  if (ch == '"') {
    std::string unused;
    return ParseJsonString(text, pos, &unused, error_message);
  }

  const std::size_t value_start = *pos;
  while (*pos < text.size()) {
    const char current = text[*pos];
    if (current == ',' || current == '}' || current == ']' || IsWhitespace(current)) {
      break;
    }
    ++(*pos);
  }

  if (*pos == value_start) {
    if (error_message != nullptr) {
      *error_message = "Expected JSON value";
    }
    return false;
  }

  return true;
}

}  // namespace

bool ParseObjectFields(std::string_view json_text, FieldMap* out_fields, std::string* error_message) {
  if (out_fields == nullptr) {
    if (error_message != nullptr) {
      *error_message = "Output field map is null";
    }
    return false;
  }

  out_fields->clear();

  std::size_t pos = 0;
  SkipWhitespace(json_text, &pos);

  if (pos >= json_text.size() || json_text[pos] != '{') {
    if (error_message != nullptr) {
      *error_message = "Top-level JSON value must be an object";
    }
    return false;
  }

  ++pos;
  SkipWhitespace(json_text, &pos);
  if (pos < json_text.size() && json_text[pos] == '}') {
    ++pos;
    SkipWhitespace(json_text, &pos);
    if (pos != json_text.size()) {
      if (error_message != nullptr) {
        *error_message = "Unexpected trailing content";
      }
      return false;
    }
    return true;
  }

  while (pos < json_text.size()) {
    std::string key;
    if (!ParseJsonString(json_text, &pos, &key, error_message)) {
      return false;
    }

    SkipWhitespace(json_text, &pos);
    if (pos >= json_text.size() || json_text[pos] != ':') {
      if (error_message != nullptr) {
        *error_message = "Expected ':' after key";
      }
      return false;
    }

    ++pos;
    SkipWhitespace(json_text, &pos);

    const std::size_t value_start = pos;
    if (!SkipJsonValue(json_text, &pos, error_message)) {
      return false;
    }

    out_fields->insert_or_assign(key, std::string(json_text.substr(value_start, pos - value_start)));

    SkipWhitespace(json_text, &pos);
    if (pos >= json_text.size()) {
      if (error_message != nullptr) {
        *error_message = "Unterminated object";
      }
      return false;
    }

    if (json_text[pos] == ',') {
      ++pos;
      SkipWhitespace(json_text, &pos);
      continue;
    }

    if (json_text[pos] == '}') {
      ++pos;
      SkipWhitespace(json_text, &pos);
      if (pos != json_text.size()) {
        if (error_message != nullptr) {
          *error_message = "Unexpected trailing content";
        }
        return false;
      }
      return true;
    }

    if (error_message != nullptr) {
      *error_message = "Expected ',' or '}'";
    }
    return false;
  }

  if (error_message != nullptr) {
    *error_message = "Unterminated object";
  }
  return false;
}

bool TryGetStringField(const FieldMap& fields, const std::string& key, std::string* out_value) {
  const auto it = fields.find(key);
  if (it == fields.end() || out_value == nullptr) {
    return false;
  }

  std::size_t pos = 0;
  std::string parsed;
  std::string ignored_error;
  if (!ParseJsonString(it->second, &pos, &parsed, &ignored_error)) {
    return false;
  }

  SkipWhitespace(it->second, &pos);
  if (pos != it->second.size()) {
    return false;
  }

  *out_value = parsed;
  return true;
}

bool TryGetIntField(const FieldMap& fields, const std::string& key, int* out_value) {
  const auto it = fields.find(key);
  if (it == fields.end() || out_value == nullptr) {
    return false;
  }

  const std::string trimmed = Trim(it->second);
  if (trimmed.empty()) {
    return false;
  }

  try {
    std::size_t processed = 0;
    const int val = std::stoi(trimmed, &processed);
    if (processed != trimmed.size()) {
      return false;
    }
    *out_value = val;
    return true;
  } catch (...) {
    return false;
  }
}

bool TryGetObjectField(
    const FieldMap& fields,
    const std::string& key,
    FieldMap* out_fields,
    std::string* error_message) {
  const auto it = fields.find(key);
  if (it == fields.end() || out_fields == nullptr) {
    return false;
  }
  return ParseObjectFields(it->second, out_fields, error_message);
}

bool TryGetRawField(const FieldMap& fields, const std::string& key, std::string* out_raw_value) {
  const auto it = fields.find(key);
  if (it == fields.end() || out_raw_value == nullptr) {
    return false;
  }
  *out_raw_value = Trim(it->second);
  return true;
}

std::string Escape(std::string_view text) {
  std::string escaped;
  escaped.reserve(text.size());

  for (const char ch : text) {
    switch (ch) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20U) {
          const char* hex = "0123456789ABCDEF";
          escaped += "\\u00";
          escaped.push_back(hex[(ch >> 4) & 0x0F]);
          escaped.push_back(hex[ch & 0x0F]);
        } else {
          escaped.push_back(ch);
        }
        break;
    }
  }

  return escaped;
}

std::string Trim(std::string_view value) {
  std::size_t begin = 0;
  std::size_t end = value.size();

  while (begin < value.size() && IsWhitespace(value[begin])) {
    ++begin;
  }
  while (end > begin && IsWhitespace(value[end - 1])) {
    --end;
  }

  return std::string(value.substr(begin, end - begin));
}

bool IsNull(std::string_view value) {
  return Trim(value) == "null";
}

}  // namespace dbgx::json
