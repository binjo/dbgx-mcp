#include "dbgx/mcp/http_server.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace dbgx::mcp {

namespace {

constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
constexpr std::size_t kMaxBodyBytes = 2 * 1024 * 1024;
constexpr std::uint16_t kDefaultMaxPortAttempts = 16;

std::uint16_t ResolveMaxPortAttempts(const HttpServerStartOptions* start_options) {
  if (start_options == nullptr || start_options->max_port_attempts == 0) {
    return kDefaultMaxPortAttempts;
  }
  return start_options->max_port_attempts;
}

bool IsPortConflictError(int error_code) {
  return error_code == WSAEADDRINUSE;
}

std::string FormatSocketError(int error_code) {
  return "WSA error " + std::to_string(error_code);
}

std::string ToLower(std::string_view value) {
  std::string lowered(value);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return lowered;
}

std::string Trim(std::string_view value) {
  std::size_t begin = 0;
  std::size_t end = value.size();

  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
    ++begin;
  }
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }

  return std::string(value.substr(begin, end - begin));
}

std::string StatusText(int status_code) {
  switch (status_code) {
    case 200:
      return "OK";
    case 202:
      return "Accepted";
    case 400:
      return "Bad Request";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 500:
      return "Internal Server Error";
    default:
      return "Error";
  }
}

bool SendAll(SOCKET socket, const std::string& text) {
  std::size_t sent_total = 0;
  while (sent_total < text.size()) {
    const int sent = send(
        socket,
        text.data() + sent_total,
        static_cast<int>(text.size() - sent_total),
        0);
    if (sent <= 0) {
      return false;
    }
    sent_total += static_cast<std::size_t>(sent);
  }
  return true;
}

bool ParseRequestLine(std::string_view line, HttpRequest* request) {
  std::size_t method_end = line.find(' ');
  if (method_end == std::string_view::npos) {
    return false;
  }
  std::size_t path_end = line.find(' ', method_end + 1);
  if (path_end == std::string_view::npos) {
    return false;
  }

  request->method = std::string(line.substr(0, method_end));
  request->path = std::string(line.substr(method_end + 1, path_end - method_end - 1));
  return true;
}

bool ParseContentLength(std::string_view value, std::size_t* out_content_length) {
  const std::string trimmed = Trim(value);
  if (trimmed.empty()) {
    return false;
  }

  std::size_t result = 0;
  for (const char ch : trimmed) {
    if (ch < '0' || ch > '9') {
      return false;
    }

    const std::size_t digit = static_cast<std::size_t>(ch - '0');
    if (result > (kMaxBodyBytes / 10)) {
      return false;
    }
    result = result * 10 + digit;
    if (result > kMaxBodyBytes) {
      return false;
    }
  }

  *out_content_length = result;
  return true;
}

bool ParseHttpRequest(
    const std::string& raw,
    std::size_t header_end,
    std::size_t body_length,
    HttpRequest* out_request,
    std::string* error_message) {
  if (out_request == nullptr) {
    if (error_message != nullptr) {
      *error_message = "Request output is null";
    }
    return false;
  }

  out_request->headers.clear();

  const std::string_view header_block(raw.data(), header_end);
  std::size_t line_start = 0;
  std::size_t line_end = header_block.find("\r\n");
  if (line_end == std::string_view::npos) {
    if (error_message != nullptr) {
      *error_message = "Malformed request line";
    }
    return false;
  }

  if (!ParseRequestLine(header_block.substr(line_start, line_end - line_start), out_request)) {
    if (error_message != nullptr) {
      *error_message = "Invalid request line";
    }
    return false;
  }

  line_start = line_end + 2;
  while (line_start < header_block.size()) {
    line_end = header_block.find("\r\n", line_start);
    if (line_end == std::string_view::npos) {
      break;
    }

    if (line_end == line_start) {
      line_start = line_end + 2;
      continue;
    }

    const std::string_view line = header_block.substr(line_start, line_end - line_start);
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos) {
      if (error_message != nullptr) {
        *error_message = "Malformed header";
      }
      return false;
    }

    const std::string key = ToLower(Trim(line.substr(0, colon)));
    const std::string value = Trim(line.substr(colon + 1));
    out_request->headers.insert_or_assign(key, value);

    line_start = line_end + 2;
  }

  out_request->body = raw.substr(header_end + 4, body_length);
  return true;
}

bool ReceiveRequest(SOCKET socket, HttpRequest* out_request, std::string* error_message) {
  std::string received;
  received.reserve(8192);

  char buffer[4096];
  std::size_t header_end = std::string::npos;
  std::size_t content_length = 0;

  while (true) {
    const int bytes = recv(socket, buffer, static_cast<int>(sizeof(buffer)), 0);
    if (bytes <= 0) {
      break;
    }

    received.append(buffer, static_cast<std::size_t>(bytes));

    if (received.size() > (kMaxHeaderBytes + kMaxBodyBytes + 4)) {
      if (error_message != nullptr) {
        *error_message = "Request is too large";
      }
      return false;
    }

    if (header_end == std::string::npos) {
      header_end = received.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        const std::string header_text(received.data(), header_end);
        std::size_t line_start = 0;
        while (line_start < header_text.size()) {
          const std::size_t line_end = header_text.find("\r\n", line_start);
          const std::size_t this_end = line_end == std::string::npos ? header_text.size() : line_end;
          const std::string_view line(header_text.data() + line_start, this_end - line_start);

          const std::size_t colon = line.find(':');
          if (colon != std::string_view::npos) {
            const std::string key = ToLower(Trim(line.substr(0, colon)));
            if (key == "content-length") {
              if (!ParseContentLength(line.substr(colon + 1), &content_length)) {
                if (error_message != nullptr) {
                  *error_message = "Invalid Content-Length";
                }
                return false;
              }
            }
          }

          if (line_end == std::string::npos) {
            break;
          }
          line_start = line_end + 2;
        }
      }
    }

    if (header_end != std::string::npos) {
      const std::size_t needed = header_end + 4 + content_length;
      if (received.size() >= needed) {
        return ParseHttpRequest(received, header_end, content_length, out_request, error_message);
      }
    }
  }

  if (error_message != nullptr) {
    *error_message = "Connection closed before full request was received";
  }
  return false;
}

std::string BuildHttpResponseText(const HttpResponse& response) {
  std::ostringstream output;
  output << "HTTP/1.1 " << response.status_code << ' ' << StatusText(response.status_code) << "\r\n";
  output << "Connection: close\r\n";

  if (response.has_body) {
    output << "Content-Type: "
           << (response.content_type.empty() ? "application/json; charset=utf-8" : response.content_type)
           << "\r\n";
    output << "Content-Length: " << response.body.size() << "\r\n";
    output << "\r\n";
    output << response.body;
  } else {
    output << "Content-Length: 0\r\n\r\n";
  }

  return output.str();
}

}  // namespace

struct HttpServer::Impl {
  std::mutex mutex;
  std::atomic<bool> running{false};
  std::atomic<bool> stop_requested{false};
  SOCKET listen_socket = INVALID_SOCKET;
  std::thread worker;
  HttpRequestHandler handler;
  std::uint16_t bound_port = 0;
  bool wsa_initialized = false;
};

bool IsOriginAllowed(std::string_view origin_header) {
  if (origin_header.empty()) {
    return true;
  }

  const std::string lowered = ToLower(Trim(origin_header));
  if (lowered.rfind("http://localhost", 0) == 0) {
    return true;
  }
  if (lowered.rfind("http://127.0.0.1", 0) == 0) {
    return true;
  }
  return false;
}

HttpServer::HttpServer() : impl_(std::make_unique<Impl>()) {}

HttpServer::~HttpServer() {
  Stop();
}

bool HttpServer::Start(
    const std::string& host,
    std::uint16_t port,
    HttpRequestHandler handler,
    std::string* error_message,
    HttpServerStartReport* start_report,
    const HttpServerStartOptions* start_options) {
  std::lock_guard<std::mutex> lock(impl_->mutex);

  std::uint16_t attempt_count = 0;
  std::uint16_t conflict_count = 0;
  std::uint16_t last_attempted_port = 0;
  std::uint16_t bound_port = 0;
  bool exhausted_conflicts = false;
  bool fallback_used = false;
  int last_error_code = 0;

  auto set_error = [&](std::string message) {
    if (error_message != nullptr) {
      *error_message = std::move(message);
    }
  };

  auto update_start_report = [&]() {
    if (start_report == nullptr) {
      return;
    }

    start_report->initial_port = port;
    start_report->last_attempted_port = last_attempted_port;
    start_report->bound_port = bound_port;
    start_report->attempt_count = attempt_count;
    start_report->conflict_count = conflict_count;
    start_report->fallback_used = fallback_used;
    start_report->exhausted_conflicts = exhausted_conflicts;
    start_report->last_error_code = last_error_code;
  };

  auto fail_start = [&](std::string message, int socket_error_code) -> bool {
    last_error_code = socket_error_code;
    update_start_report();
    set_error(std::move(message));

    if (impl_->listen_socket != INVALID_SOCKET) {
      closesocket(impl_->listen_socket);
      impl_->listen_socket = INVALID_SOCKET;
    }
    impl_->bound_port = 0;

    if (impl_->wsa_initialized) {
      WSACleanup();
      impl_->wsa_initialized = false;
    }
    return false;
  };

  impl_->listen_socket = INVALID_SOCKET;
  impl_->bound_port = 0;

  if (impl_->running.load()) {
    set_error("Server is already running");
    update_start_report();
    return false;
  }

  WSADATA wsa_data{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    set_error("WSAStartup failed");
    update_start_report();
    return false;
  }
  impl_->wsa_initialized = true;

  in_addr host_address{};
  if (inet_pton(AF_INET, host.c_str(), &host_address) != 1) {
    return fail_start("Invalid bind host", 0);
  }

  const std::uint16_t max_port_attempts = ResolveMaxPortAttempts(start_options);
  for (std::uint16_t offset = 0; offset < max_port_attempts; ++offset) {
    const std::uint32_t candidate_port_raw = static_cast<std::uint32_t>(port) + offset;
    if (candidate_port_raw > (std::numeric_limits<std::uint16_t>::max)()) {
      exhausted_conflicts = true;
      break;
    }

    last_attempted_port = static_cast<std::uint16_t>(candidate_port_raw);
    ++attempt_count;

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
      const int socket_error = WSAGetLastError();
      return fail_start(
          "Failed to create listening socket (" + FormatSocketError(socket_error) + ")",
          socket_error);
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(last_attempted_port);
    address.sin_addr = host_address;

    if (bind(listen_socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      const int bind_error = WSAGetLastError();
      closesocket(listen_socket);

      if (IsPortConflictError(bind_error)) {
        ++conflict_count;
        last_error_code = bind_error;
        continue;
      }

      return fail_start(
          "Bind failed on port " + std::to_string(last_attempted_port) +
              " (" + FormatSocketError(bind_error) + ")",
          bind_error);
    }

    if (listen(listen_socket, SOMAXCONN) != 0) {
      const int listen_error = WSAGetLastError();
      closesocket(listen_socket);
      return fail_start(
          "Listen failed on port " + std::to_string(last_attempted_port) +
              " (" + FormatSocketError(listen_error) + ")",
          listen_error);
    }

    impl_->listen_socket = listen_socket;
    break;
  }

  if (impl_->listen_socket == INVALID_SOCKET) {
    exhausted_conflicts = conflict_count > 0 && conflict_count == attempt_count;
    std::ostringstream error_stream;
    error_stream << "Failed to bind HTTP server starting at port " << port << " after "
                 << attempt_count << " attempt(s)";
    if (exhausted_conflicts) {
      error_stream << " (all attempts hit address-in-use)";
    } else if (last_error_code != 0) {
      error_stream << " (" << FormatSocketError(last_error_code) << ")";
    }
    return fail_start(error_stream.str(), last_error_code);
  }

  sockaddr_in bound_address{};
  int bound_address_length = sizeof(bound_address);
  if (getsockname(
          impl_->listen_socket,
          reinterpret_cast<sockaddr*>(&bound_address),
          &bound_address_length) == 0) {
    impl_->bound_port = ntohs(bound_address.sin_port);
  } else {
    impl_->bound_port = last_attempted_port;
  }

  bound_port = impl_->bound_port;
  fallback_used = (port != 0 && bound_port != port);
  update_start_report();

  impl_->handler = std::move(handler);
  impl_->stop_requested.store(false);
  impl_->running.store(true);

  impl_->worker = std::thread([this]() {
    while (!impl_->stop_requested.load()) {
      fd_set read_set;
      FD_ZERO(&read_set);
      FD_SET(impl_->listen_socket, &read_set);

      timeval timeout{};
      timeout.tv_sec = 0;
      timeout.tv_usec = 200000;

      const int select_result = select(0, &read_set, nullptr, nullptr, &timeout);
      if (select_result <= 0) {
        continue;
      }

      SOCKET client_socket = accept(impl_->listen_socket, nullptr, nullptr);
      if (client_socket == INVALID_SOCKET) {
        continue;
      }

      HttpRequest request;
      std::string parse_error;
      HttpResponse response;
      if (ReceiveRequest(client_socket, &request, &parse_error)) {
        response = impl_->handler(request);
      } else {
        response.status_code = 400;
        response.body = "{\"error\":\"" + parse_error + "\"}";
      }

      const std::string response_text = BuildHttpResponseText(response);
      SendAll(client_socket, response_text);
      shutdown(client_socket, SD_BOTH);
      closesocket(client_socket);
    }

    impl_->running.store(false);
  });

  return true;
}

void HttpServer::Stop() {
  std::lock_guard<std::mutex> lock(impl_->mutex);

  if (!impl_->running.load() && impl_->listen_socket == INVALID_SOCKET) {
    if (impl_->worker.joinable()) {
      impl_->worker.join();
    }
    return;
  }

  impl_->stop_requested.store(true);

  if (impl_->listen_socket != INVALID_SOCKET) {
    shutdown(impl_->listen_socket, SD_BOTH);
    closesocket(impl_->listen_socket);
    impl_->listen_socket = INVALID_SOCKET;
  }

  if (impl_->worker.joinable()) {
    impl_->worker.join();
  }

  impl_->running.store(false);

  if (impl_->wsa_initialized) {
    WSACleanup();
    impl_->wsa_initialized = false;
  }
}

bool HttpServer::IsRunning() const {
  return impl_->running.load();
}

std::uint16_t HttpServer::BoundPort() const {
  return impl_->bound_port;
}

}  // namespace dbgx::mcp
