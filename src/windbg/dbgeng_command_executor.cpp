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

HRESULT EvaluateExtendedExpressionSafe(
    IDebugHostEvaluator2* evaluator,
    const wchar_t* expression,
    IModelObject** result_obj) {
  __try {
    return evaluator->EvaluateExtendedExpression(nullptr, expression, nullptr, result_obj, nullptr);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

}  // namespace

DbgEngCommandExecutor::DbgEngCommandExecutor() {
  if (SUCCEEDED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client_.GetAddressOf())))) {
    (void)client_.As(&control_);
  }

  // Create a separate IDebugControl in the MTA so background HTTP threads can call SetInterrupt 
  // directly without COM marshalling to the main thread (which lacks a message pump in headless cdb.exe).
  std::thread init_thread([this]() {
    (void)CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Microsoft::WRL::ComPtr<IDebugClient> mta_client;
    if (SUCCEEDED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(mta_client.GetAddressOf())))) {
      (void)mta_client.As(&interrupt_control_);
    }
    CoUninitialize();
  });
  init_thread.join();

  worker_thread_ = std::thread(&DbgEngCommandExecutor::WorkerThreadProc, this);
}

DbgEngCommandExecutor::~DbgEngCommandExecutor() {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    shutdown_ = true;
  }
  cv_.notify_one();
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

CommandExecutionResult DbgEngCommandExecutor::Execute(const std::string& command, const CommandExecutionOptions& options) {
  auto state = GetExecutionState();
  if (!state.ready_for_commands) {
    return {
        false,
        "",
        "Debugger is not ready for commands (status: " + state.status_name + "). "
        "Query execution state first and call windbg.interrupt if you need to break in."
    };
  }

  std::promise<CommandExecutionResult> promise;
  std::future<CommandExecutionResult> future = promise.get_future();

  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    task_queue_.push(ExecutionTask{command, options, std::move(promise)});
  }
  cv_.notify_one();
  return future.get();
}

void DbgEngCommandExecutor::WorkerThreadProc() {
  (void)CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  while (true) {
    ExecutionTask task;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      cv_.wait(lock, [this] { return shutdown_ || !task_queue_.empty(); });
      if (shutdown_ && task_queue_.empty()) {
        break;
      }
      task = std::move(task_queue_.front());
      task_queue_.pop();
    }

    CommandExecutionResult result = ExecuteSynchronously(task.command, task.options);
    task.promise.set_value(result);
  }
  CoUninitialize();
}

CommandExecutionResult DbgEngCommandExecutor::ExecuteSynchronously(const std::string& command, const CommandExecutionOptions& options) {
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

  control->ControlledOutput(DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_NORMAL, "[windbg-mcp] [Background Job] Executing: %s\n", command.c_str());

  hr = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_DEFAULT);

  control->ControlledOutput(DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_NORMAL, "[windbg-mcp] [Background Job] Completed. (Status: %s)\n", SUCCEEDED(hr) ? "Success" : "Failed/Interrupted");

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

DebuggerExecutionState DbgEngCommandExecutor::GetExecutionState() {
  if (control_ == nullptr) {
    return {};
  }

  ULONG raw_status = 0;
  if (FAILED(control_->GetExecutionStatus(&raw_status))) {
    return {};
  }
  return ParseRawStatus(raw_status);
}

bool DbgEngCommandExecutor::InterruptTarget() {
  if (interrupt_control_ != nullptr) {
    return SUCCEEDED(interrupt_control_->SetInterrupt(DEBUG_INTERRUPT_ACTIVE));
  }
  if (control_ != nullptr) {
    return SUCCEEDED(control_->SetInterrupt(DEBUG_INTERRUPT_ACTIVE));
  }
  return false;
}

DebuggerExecutionState DbgEngCommandExecutor::ParseRawStatus(std::uint32_t raw_status) {
  DebuggerExecutionState state;
  state.raw_status = raw_status;
  
  switch (raw_status) {
    case DEBUG_STATUS_GO:
      state.status_name = "go";
      state.running = true;
      state.summary = "The target is running.";
      break;
    case DEBUG_STATUS_BREAK:
      state.status_name = "break";
      state.ready_for_commands = true;
      state.summary = "The target is broken in and ready for commands.";
      break;
    case DEBUG_STATUS_NO_DEBUGGEE:
      state.status_name = "no_debuggee";
      state.summary = "No debuggee is active.";
      break;
    default:
      state.status_name = "busy";
      state.busy = true;
      state.summary = "The debugger is busy or processing events.";
      break;
  }
  return state;
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
  if (FAILED(EvaluateExtendedExpressionSafe(evaluator.Get(), wexpr.data(), &result_obj))) {
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

CommandExecutionResult DbgEngCommandExecutor::WriteMemory(std::uint64_t address, const std::string& hex_data) {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  Microsoft::WRL::ComPtr<IDebugDataSpaces> data;
  if (FAILED(client.As(&data))) {
    return {false, "", "IDebugDataSpaces not available"};
  }

  std::vector<unsigned char> buffer;
  buffer.reserve(hex_data.size() / 2);
  for (size_t i = 0; i < hex_data.size(); ++i) {
    if (isxdigit(hex_data[i])) {
      if (i + 1 < hex_data.size() && isxdigit(hex_data[i + 1])) {
        char hex[3] = {hex_data[i], hex_data[i + 1], 0};
        buffer.push_back(static_cast<unsigned char>(strtoul(hex, nullptr, 16)));
        i++;
      }
    }
  }

  if (buffer.empty()) {
    return {false, "", "Empty or invalid hex data"};
  }

  ULONG bytes_written = 0;
  HRESULT hr = data->WriteVirtual(address, buffer.data(), (ULONG)buffer.size(), &bytes_written);
  if (FAILED(hr)) {
    return {false, "", "WriteVirtual failed: " + HResultToString(hr)};
  }

  mcp::JsonWriter writer;
  writer.StartObject();
  writer.Key("bytes_written");
  writer.IntValue(bytes_written);
  writer.EndObject();

  return {true, writer.GetJSON(), ""};
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

CommandExecutionResult DbgEngCommandExecutor::GetThreads() {
  Microsoft::WRL::ComPtr<IDebugClient> client;
  if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
    return {false, "", "DebugCreate failed"};
  }

  Microsoft::WRL::ComPtr<IDebugSystemObjects> systems;
  if (FAILED(client.As(&systems))) {
    return {false, "", "IDebugSystemObjects not available"};
  }

  ULONG num_threads = 0;
  if (FAILED(systems->GetNumberThreads(&num_threads)) || num_threads == 0) {
    return {false, "", "Failed to get thread count or no threads active"};
  }

  std::vector<ULONG> ids(num_threads);
  std::vector<ULONG> sys_ids(num_threads);
  if (FAILED(systems->GetThreadIdsByIndex(0, num_threads, ids.data(), sys_ids.data()))) {
    return {false, "", "GetThreadIdsByIndex failed"};
  }

  ULONG current_id = 0;
  systems->GetCurrentThreadId(&current_id);

  mcp::JsonWriter writer;
  writer.StartArray();
  for (ULONG i = 0; i < num_threads; ++i) {
    writer.StartObject();
    writer.Key("thread_index");
    writer.IntValue(ids[i]);
    writer.Key("system_thread_id");
    writer.IntValue(sys_ids[i]);
    writer.Key("is_current");
    writer.BoolValue(ids[i] == current_id);
    writer.EndObject();
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
      if (type == DEBUG_CLASS_USER_WINDOWS) {
        metadata.debuggee_class = "user";
      } else if (type == DEBUG_CLASS_KERNEL) {
        metadata.debuggee_class = "kernel";
      } else {
        metadata.debuggee_class = "other (" + std::to_string(type) + ")";
      }
    }

    ULONG proc_type = 0;
    if (SUCCEEDED(control->GetEffectiveProcessorType(&proc_type))) {
      switch (proc_type) {
        case IMAGE_FILE_MACHINE_I386:
          metadata.architecture = "x86";
          break;
        case IMAGE_FILE_MACHINE_AMD64:
          metadata.architecture = "x64";
          break;
        case IMAGE_FILE_MACHINE_ARM64:
          metadata.architecture = "arm64";
          break;
        case IMAGE_FILE_MACHINE_ARM:
          metadata.architecture = "arm";
          break;
        default:
          metadata.architecture = "unknown (0x" + std::to_string(proc_type) + ")";
          break;
      }
    }
  }

  return metadata;
}

}  // namespace dbgx::windbg
