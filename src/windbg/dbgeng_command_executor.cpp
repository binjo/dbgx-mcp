#include "dbgx/windbg/dbgeng_command_executor.hpp"

#include <windows.h>

#include <DbgEng.h>
#include <wrl/client.h>

#include <mutex>

namespace dbgx::windbg {

namespace {

class OutputCaptureCallbacks final : public IDebugOutputCallbacks {
 public:
  OutputCaptureCallbacks() = default;

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
      output_ += text;
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

CommandExecutionResult DbgEngCommandExecutor::Execute(const std::string& command) {
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

  auto* capture = new OutputCaptureCallbacks();
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

}  // namespace dbgx::windbg
