#pragma once

#include <string>
#include <vector>
#include <string_view>

namespace dbgx::mcp {

class JsonWriter {
 public:
  JsonWriter();

  void StartArray();
  void EndArray();

  void StartObject();
  void EndObject();

  void Key(std::string_view key);

  void StringValue(std::string_view val);
  void HexValue(std::uint64_t val);
  void IntValue(std::int64_t val);
  void UintValue(std::uint64_t val);
  void BoolValue(bool val);
  void NullValue();

  // Low-level: Write raw JSON snippet (caller ensures validity)
  void RawValue(std::string_view json);

  std::string GetJSON() const { return json_; }

 private:
  struct Scope {
    bool is_array;
    bool has_items;
    bool is_key_pending;
  };

  void MaybeComma();
  static std::string Escape(std::string_view s);

  std::string json_;
  std::vector<Scope> stack_;
};

inline JsonWriter::JsonWriter() {
  stack_.push_back({false, false, false});
}

inline void JsonWriter::StartArray() {
  MaybeComma();
  json_ += '[';
  stack_.push_back({true, false, false});
}

inline void JsonWriter::EndArray() {
  json_ += ']';
  stack_.pop_back();
  if (!stack_.empty()) {
    stack_.back().has_items = true;
    stack_.back().is_key_pending = false;
  }
}

inline void JsonWriter::StartObject() {
  MaybeComma();
  json_ += '{';
  stack_.push_back({false, false, false});
}

inline void JsonWriter::EndObject() {
  json_ += '}';
  stack_.pop_back();
  if (!stack_.empty()) {
    stack_.back().has_items = true;
    stack_.back().is_key_pending = false;
  }
}

inline void JsonWriter::Key(std::string_view key) {
  MaybeComma();
  json_ += '"';
  json_ += Escape(key);
  json_ += "\":";
  stack_.back().is_key_pending = true;
}

inline void JsonWriter::StringValue(std::string_view val) {
  MaybeComma();
  json_ += '"';
  json_ += Escape(val);
  json_ += '"';
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::HexValue(std::uint64_t val) {
  MaybeComma();
  char buf[32];
  snprintf(buf, sizeof(buf), "\"0x%llx\"", val);
  json_ += buf;
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::IntValue(std::int64_t val) {
  MaybeComma();
  json_ += std::to_string(val);
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::UintValue(std::uint64_t val) {
  MaybeComma();
  json_ += std::to_string(val);
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::BoolValue(bool val) {
  MaybeComma();
  json_ += val ? "true" : "false";
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::NullValue() {
  MaybeComma();
  json_ += "null";
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::RawValue(std::string_view json) {
  MaybeComma();
  json_ += json;
  stack_.back().has_items = true;
  stack_.back().is_key_pending = false;
}

inline void JsonWriter::MaybeComma() {
  if (stack_.size() <= 1) return;
  auto& scope = stack_.back();
  if (scope.has_items && (scope.is_array || !scope.is_key_pending)) {
    json_ += ',';
  }
}

}  // namespace dbgx::mcp