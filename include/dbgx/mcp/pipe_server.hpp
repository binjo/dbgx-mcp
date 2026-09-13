#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace dbgx::mcp {

using PipeRequestHandler = std::function<std::string(const std::string& request_json)>;

class PipeServer {
public:
  PipeServer();
  ~PipeServer();

  PipeServer(const PipeServer&) = delete;
  PipeServer& operator=(const PipeServer&) = delete;

  bool Start(const std::string& pipe_name, PipeRequestHandler handler, std::string* error_message = nullptr);
  void Stop();

  bool IsRunning() const;
  const std::string& PipeName() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace dbgx::mcp
