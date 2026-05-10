#include "dbgx/windbg/dbgeng_command_executor.hpp"

#include <windows.h>

#include <DbgEng.h>
#include <wrl/client.h>

#include <cctype>
#include <cstdlib>
#include <mutex>
#include <vector>

#include "dbgx/mcp/json_writer.hpp"
#include "dbgx/windbg/model_serializer.hpp"

namespace dbgx::windbg {

namespace {

class OutputCaptureCallbacks final : public IDebugOutputCallbacks {
 public:
  explicit OutputCaptureCallbacks(const CommandExecutionOptions& options) : options_(options) {}

  STDMETHOD(QueryInterface)(REFIID interface_id, PVOID* out) override {
    if (out == nullptr) {
      return E_INVALIDARG;
    }

    if (interface_id == __uuidof(IUnknown) || interface_id == __uuidof(IDebugOutputCallbacks)) {
      *out = static_cast<IDebugOutputCallbacks*>(this);
      AddRef();
      return S_OK;
    }

    *out = nullptr;
    return E_NOINTERFACE;
  }

  STDMETHOD_(ULONG, AddRef)() override {
    return static_cast<ULONG>(InterlockedIncrement(&ref_count_));
  }

  STDMETHOD_(ULONG, Release)() override {
    const ULONG count = static_cast<ULONG>(InterlockedDecrement(&ref_count_));
    if (count == 0) {
      delete this;
    }
    return count;
  }

  STDMETHOD(Output)(ULONG /*mask*/, PCSTR text) override {
    if (text != nullptr) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (truncated_) {
        return S_OK;
      }

      std::string input(text);
      std::size_t start = 0;
      while (start < input.size()) {
        std::size_t end = input.find('\n', start);
        std::string line;
        if (end == std::string::npos) {
          line = input.substr(start);
          start = input.size();
        } else {
          line = input.substr(start, end - start + 1);
          start = end + 1;
        }

        if (!options_.pattern.empty()) {
          if (line.find(options_.pattern) == std::string::npos) {
            continue;
          }
        }

        if (line_count_ < options_.max_lines) {
          output_ += line;
          if (!line.empty() && line.back() == '\n') {
            line_count_++;
          }
        } else {
          output_ += "\n[... truncated ...]\n";
          truncated_ = true;
          break;
        }
      }
    }
    return S_OK;
  }

  std::string TakeOutput() {
    std::lock_guard<std::mutex> lock(mutex_);
    return output_;
  }

 private:
  volatile LONG ref_count_ = 1;
  std::mutex mutex_;
  std::string output_;
  CommandExecutionOptions options_;
  int line_count_ = 0;
  bool truncated_ = false;
};

std::string HResultToString(HRESULT hr) {
  char* raw = nullptr;
  const DWORD size = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      static_cast<DWORD>(hr),
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&raw),
      0,
      nullptr);

  std::string message;
  if (size != 0 && raw != nullptr) {
    message.assign(raw, size);
    LocalFree(raw);
  } else {
    message = "HRESULT=0x";
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (int shift = 28; shift >= 0; shift -= 4) {
      message.push_back(kHex[(hr >> shift) & 0x0F]);
    }
  }
  return message;
}

}  // namespace

CommandExecutionResult DbgEngCommandExecutor::Execute(const std::string& command, const CommandExecutionOptions& options) {
  if (command.empty()) {
    return {false, "", "Command cannot be empty"};
  }

  Microsoft::WRL::ComPtr<IDebugClient> client;
  HRESULT hr = DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf()));
  if (FAILED(hr)) {
    return {
        false,
        "",
        "DebugCreate failed: " + HResultToString(hr),
    };
  }

  Microsoft::WRL::ComPtr<IDebugControl> control;
  hr = client.As(&control);
  if (FAILED(hr)) {
    return {
        false,
        "",
        "IDebugControl not available: " + HResultToString(hr),
    };
  }

  Microsoft::WRL::ComPtr<IDebugOutputCallbacks> previous_callbacks;
  (void)client->GetOutputCallbacks(&previous_callbacks);

  auto* capture = new OutputCaptureCallbacks(options);
  hr = client->SetOutputCallbacks(capture);
  if (FAILED(hr)) {
    capture->Release();
    return {
        false,
        "",
        "SetOutputCallbacks failed: " + HResultToString(hr),
    };
  }

  hr = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_DEFAULT);

  (void)client->SetOutputCallbacks(previous_callbacks.Get());

  const std::string output = capture->TakeOutput();
  capture->Release();

  if (FAILED(hr)) {
    return {
        false,
        output,
        "IDebugControl::Execute failed: " + HResultToString(hr),
    };
  }

  return {
      true,
      output,
      "",
  };
}

CommandExecutionResult DbgEngCommandExecutor::EvaluateModel(const std::string& expression, int max_depth) {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  Microsoft::WRL::ComPtr<IHostDataModelAccess> access;
  if (FAILED(client.As(&access))) {
    return {false, "", "IHostDataModelAccess not available"};
  }

  Microsoft::WRL::ComPtr<IDataModelManager> manager;
  Microsoft::WRL::ComPtr<IDebugHost> host;
  if (FAILED(access->GetDataModel(&manager, &host))) {
    return {false, "", "Failed to get Data Model"};
  }

  Microsoft::WRL::ComPtr<IDebugHostEvaluator2> evaluator;
  if (FAILED(host.As(&evaluator))) {
    return {false, "", "IDebugHostEvaluator2 not available"};
  }

  int wlen = MultiByteToWideChar(CP_UTF8, 0, expression.c_str(), -1, nullptr, 0);
  std::vector<wchar_t> wexpr(wlen);
  MultiByteToWideChar(CP_UTF8, 0, expression.c_str(), -1, wexpr.data(), wlen);

  Microsoft::WRL::ComPtr<IModelObject> result_obj;
  if (FAILED(evaluator->EvaluateExtendedExpression(nullptr, wexpr.data(), nullptr, &result_obj, nullptr))) {
    return {false, "", "Expression evaluation failed"};
  }

  mcp::JsonWriter writer;
  ModelSerializer::Serialize(result_obj.Get(), writer, max_depth);

  return {true, writer.GetJSON(), ""};
}

CommandExecutionResult DbgEngCommandExecutor::GetContextSnapshot() {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  mcp::JsonWriter writer;
  writer.StartObject();

  // 1. Registers
  Microsoft::WRL::ComPtr<IDebugRegisters> registers;
  if (SUCCEEDED(client.As(&registers))) {
    writer.Key("registers");
    writer.StartObject();
    ULONG count = 0;
    registers->GetNumberRegisters(&count);
    for (ULONG i = 0; i < count; ++i) {
      char name[64];
      if (SUCCEEDED(registers->GetDescription(i, name, sizeof(name), nullptr, nullptr))) {
        DEBUG_VALUE val;
        if (SUCCEEDED(registers->GetValue(i, &val))) {
          if (val.Type == DEBUG_VALUE_INT64) {
            writer.Key(name);
            writer.HexValue(val.I64);
          } else if (val.Type == DEBUG_VALUE_INT32) {
            writer.Key(name);
            writer.HexValue(val.I32);
          }
        }
      }
    }
    writer.EndObject();
  }

  // 2. Stack
  Microsoft::WRL::ComPtr<IDebugControl> control;
  if (SUCCEEDED(client.As(&control))) {
    writer.Key("stack");
    writer.StartArray();
    DEBUG_STACK_FRAME frames[20];
    ULONG filled = 0;
    if (SUCCEEDED(control->GetStackTrace(0, 0, 0, frames, 20, &filled))) {
      Microsoft::WRL::ComPtr<IDebugSymbols> symbols;
      client.As(&symbols);
      for (ULONG i = 0; i < filled; ++i) {
        writer.StartObject();
        writer.Key("instruction_offset");
        writer.HexValue(frames[i].InstructionOffset);
        if (symbols) {
          char name[256];
          ULONG64 disp = 0;
          if (SUCCEEDED(symbols->GetNameByOffset(frames[i].InstructionOffset, name, sizeof(name), nullptr, &disp))) {
            writer.Key("symbol");
            std::string sym = name;
            if (disp > 0) sym += "+0x" + std::to_string(disp);
            writer.StringValue(sym);
          }
        }
        writer.EndObject();
      }
    }
    writer.EndArray();
  }

  writer.EndObject();
  return {true, writer.GetJSON(), ""};
}

CommandExecutionResult DbgEngCommandExecutor::ReadMemory(std::uint64_t address, std::uint32_t length) {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  Microsoft::WRL::ComPtr<IDebugDataSpaces> data;
  if (FAILED(client.As(&data))) {
    return {false, "", "IDebugDataSpaces not available"};
  }

  if (length > 1024 * 1024) length = 1024 * 1024; // Limit to 1MB

  std::vector<unsigned char> buffer(length);
  ULONG bytes_read = 0;
  HRESULT hr = data->ReadVirtual(address, buffer.data(), length, &bytes_read);
  if (FAILED(hr) && bytes_read == 0) {
    return {false, "", "ReadVirtual failed: " + HResultToString(hr)};
  }

  std::string hex;
  hex.reserve(bytes_read * 2);
  static const char* kDigits = "0123456789abcdef";
  for (ULONG i = 0; i < bytes_read; ++i) {
    hex.push_back(kDigits[buffer[i] >> 4]);
    hex.push_back(kDigits[buffer[i] & 0x0f]);
  }

  return {true, hex, ""};
}

CommandExecutionResult DbgEngCommandExecutor::SearchMemory(
    std::uint64_t start_address,
    std::uint64_t end_address,
    const std::string& pattern) {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  Microsoft::WRL::ComPtr<IDebugDataSpaces> data;
  if (FAILED(client.As(&data))) {
    return {false, "", "IDebugDataSpaces not available"};
  }

  std::vector<unsigned char> pattern_bytes;
  for (size_t i = 0; i < pattern.size(); ++i) {
    if (isxdigit(pattern[i])) {
      if (i + 1 < pattern.size() && isxdigit(pattern[i + 1])) {
        char hex[3] = {pattern[i], pattern[i + 1], 0};
        pattern_bytes.push_back(static_cast<unsigned char>(strtoul(hex, nullptr, 16)));
        i++;
      }
    }
  }

  if (pattern_bytes.empty()) {
    return {false, "", "Empty or invalid pattern"};
  }

  mcp::JsonWriter writer;
  writer.StartArray();

  ULONG64 found_addr = 0;
  ULONG64 current = start_address;
  while (current < end_address) {
    if (SUCCEEDED(data->SearchVirtual(current, end_address - current, pattern_bytes.data(), (ULONG)pattern_bytes.size(), 1, &found_addr))) {
      writer.HexValue(found_addr);
      current = found_addr + 1;
    } else {
      break;
    }
  }

  writer.EndArray();
  return {true, writer.GetJSON(), ""};
}

SessionMetadata DbgEngCommandExecutor::GetSessionMetadata() {
  SessionMetadata metadata;
  metadata.process_id = GetCurrentProcessId();

  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return metadata;
  }

  Microsoft::WRL::ComPtr<IDebugSystemObjects> systems;
  if (SUCCEEDED(client.As(&systems))) {
    ULONG pid = 0;
    if (SUCCEEDED(systems->GetCurrentProcessSystemId(&pid))) {
      metadata.process_id = static_cast<std::uint32_t>(pid);
    }

    char exe_name[MAX_PATH];
    if (SUCCEEDED(systems->GetCurrentProcessExecutableName(exe_name, sizeof(exe_name), nullptr))) {
      metadata.executable_name = exe_name;
    }
  }

  Microsoft::WRL::ComPtr<IDebugControl> control;
  if (SUCCEEDED(client.As(&control))) {
    ULONG type = 0;
    ULONG qual = 0;
    if (SUCCEEDED(control->GetDebuggeeType(&type, &qual))) {
      metadata.target_info = "Type=" + std::to_string(type) + ", Qual=" + std::to_string(qual);
    }
  }

  return metadata;
}

}  // namespace dbgx::windbg
