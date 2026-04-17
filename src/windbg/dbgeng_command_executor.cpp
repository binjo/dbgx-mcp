#include "dbgx/windbg/dbgeng_command_executor.hpp"

#include <windows.h>

#include <DbgEng.h>
#include <wrl/client.h>

#include <mutex>

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
