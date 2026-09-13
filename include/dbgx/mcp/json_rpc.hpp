#pragma once

#include <string>
#include <string_view>

#include "dbgx/windbg/command_executor.hpp"

namespace dbgx::mcp {

struct JsonRpcHttpResult {
  int status_code = 200;
  std::string content_type = "application/json; charset=utf-8";
  std::string body;
  bool has_body = true;
};

class JsonRpcRouter {
public:
  explicit JsonRpcRouter(windbg::IWinDbgCommandExecutor* executor);

  JsonRpcHttpResult HandleJsonRpcPost(std::string_view request_body) const;

private:
  windbg::IWinDbgCommandExecutor* executor_;
};

}  // namespace dbgx::mcp
