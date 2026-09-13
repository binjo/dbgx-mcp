#include "dbgx/mcp/pipe_server.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <objbase.h>
#include <windows.h>

namespace dbgx::mcp {

struct PipeServer::Impl {
  std::mutex mutex;
  std::atomic<bool> running{false};
  std::atomic<bool> stop_requested{false};
  std::string pipe_name;
  std::string full_pipe_path;
  PipeRequestHandler handler;
  HANDLE stop_event = NULL;
  std::thread listener_thread;

  std::mutex clients_mutex;
  std::condition_variable clients_cv;
  std::vector<HANDLE> active_pipes;
  std::vector<std::thread> client_threads;
};

PipeServer::PipeServer() : impl_(std::make_unique<Impl>()) {}

PipeServer::~PipeServer() {
  Stop();
}

bool PipeServer::Start(const std::string& pipe_name, PipeRequestHandler handler, std::string* error_message) {
  std::lock_guard<std::mutex> lock(impl_->mutex);

  if (impl_->running.load()) {
    if (error_message) {
      *error_message = "Pipe server is already running";
    }
    return false;
  }

  if (pipe_name.empty()) {
    if (error_message) {
      *error_message = "Pipe name cannot be empty";
    }
    return false;
  }

  impl_->pipe_name = pipe_name;
  if (pipe_name.rfind("\\\\.\\pipe\\", 0) == 0) {
    impl_->full_pipe_path = pipe_name;
  } else {
    impl_->full_pipe_path = "\\\\.\\pipe\\" + pipe_name;
  }

  impl_->handler = std::move(handler);
  impl_->stop_requested.store(false);
  impl_->stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (impl_->stop_event == NULL) {
    if (error_message) {
      *error_message = "Failed to create stop event (Error " + std::to_string(GetLastError()) + ")";
    }
    return false;
  }

  HANDLE ready_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  impl_->running.store(true);

  impl_->listener_thread = std::thread([this, ready_event]() {
    bool signaled_ready = false;

    while (!impl_->stop_requested.load()) {
      HANDLE pipe_handle = CreateNamedPipeA(impl_->full_pipe_path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                                            65536, 65536, 5000, NULL);

      if (pipe_handle == INVALID_HANDLE_VALUE) {
        if (impl_->stop_requested.load()) {
          break;
        }
        Sleep(50);
        continue;
      }

      if (!signaled_ready && ready_event != NULL) {
        SetEvent(ready_event);
        signaled_ready = true;
      }

      OVERLAPPED connect_ov{};
      connect_ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
      if (connect_ov.hEvent == NULL) {
        CloseHandle(pipe_handle);
        continue;
      }

      BOOL connected = ConnectNamedPipe(pipe_handle, &connect_ov);
      DWORD last_error = GetLastError();

      bool client_ready = false;
      if (connected) {
        client_ready = true;
      } else if (last_error == ERROR_PIPE_CONNECTED) {
        client_ready = true;
      } else if (last_error == ERROR_IO_PENDING) {
        HANDLE wait_handles[2] = {impl_->stop_event, connect_ov.hEvent};
        DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0 + 1) {
          DWORD bytes_transferred = 0;
          if (GetOverlappedResult(pipe_handle, &connect_ov, &bytes_transferred, FALSE)) {
            client_ready = true;
          }
        } else {
          CancelIo(pipe_handle);
        }
      }

      CloseHandle(connect_ov.hEvent);

      if (!client_ready || impl_->stop_requested.load()) {
        DisconnectNamedPipe(pipe_handle);
        CloseHandle(pipe_handle);
        if (impl_->stop_requested.load()) {
          break;
        }
        continue;
      }

      {
        std::lock_guard<std::mutex> clients_lock(impl_->clients_mutex);
        impl_->active_pipes.push_back(pipe_handle);
      }

      std::thread client_worker([this, pipe_handle]() {
        (void)CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        std::string buffer;
        buffer.reserve(8192);
        char read_chunk[4096];

        while (!impl_->stop_requested.load()) {
          OVERLAPPED read_ov{};
          read_ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
          if (read_ov.hEvent == NULL) {
            break;
          }

          DWORD bytes_read = 0;
          BOOL read_ok = ReadFile(pipe_handle, read_chunk, sizeof(read_chunk), &bytes_read, &read_ov);
          if (!read_ok) {
            DWORD read_err = GetLastError();
            if (read_err == ERROR_IO_PENDING) {
              HANDLE wait_handles[2] = {impl_->stop_event, read_ov.hEvent};
              DWORD wr = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
              if (wr == WAIT_OBJECT_0 + 1) {
                if (!GetOverlappedResult(pipe_handle, &read_ov, &bytes_read, FALSE)) {
                  CloseHandle(read_ov.hEvent);
                  break;
                }
              } else {
                CancelIo(pipe_handle);
                CloseHandle(read_ov.hEvent);
                break;
              }
            } else {
              CloseHandle(read_ov.hEvent);
              break;
            }
          }
          CloseHandle(read_ov.hEvent);

          if (bytes_read == 0) {
            break;
          }

          buffer.append(read_chunk, static_cast<std::size_t>(bytes_read));

          // Process all complete newline-delimited requests in buffer
          while (true) {
            std::size_t newline_pos = buffer.find('\n');
            if (newline_pos == std::string::npos) {
              break;
            }

            std::string request_line = buffer.substr(0, newline_pos);
            buffer.erase(0, newline_pos + 1);

            // Strip trailing \r if present
            while (!request_line.empty() && (request_line.back() == '\r' || request_line.back() == ' ')) {
              request_line.pop_back();
            }

            if (request_line.empty()) {
              continue;
            }

            std::string response_line;
            if (impl_->handler) {
              response_line = impl_->handler(request_line);
            } else {
              response_line =
                  "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Handler not available\"}}";
            }

            response_line.push_back('\n');

            DWORD total_written = 0;
            while (total_written < response_line.size()) {
              OVERLAPPED write_ov{};
              write_ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
              if (write_ov.hEvent == NULL) {
                break;
              }

              DWORD written = 0;
              BOOL write_ok = WriteFile(pipe_handle, response_line.data() + total_written,
                                        static_cast<DWORD>(response_line.size() - total_written), &written, &write_ov);

              if (!write_ok) {
                if (GetLastError() == ERROR_IO_PENDING) {
                  HANDLE wait_handles[2] = {impl_->stop_event, write_ov.hEvent};
                  DWORD wr = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
                  if (wr == WAIT_OBJECT_0 + 1) {
                    GetOverlappedResult(pipe_handle, &write_ov, &written, FALSE);
                  } else {
                    CancelIo(pipe_handle);
                    CloseHandle(write_ov.hEvent);
                    break;
                  }
                } else {
                  CloseHandle(write_ov.hEvent);
                  break;
                }
              }
              CloseHandle(write_ov.hEvent);

              if (written == 0) {
                break;
              }
              total_written += written;
            }
            FlushFileBuffers(pipe_handle);
          }
        }

        FlushFileBuffers(pipe_handle);
        DisconnectNamedPipe(pipe_handle);
        CloseHandle(pipe_handle);

        {
          std::lock_guard<std::mutex> clients_lock(impl_->clients_mutex);
          auto it = std::find(impl_->active_pipes.begin(), impl_->active_pipes.end(), pipe_handle);
          if (it != impl_->active_pipes.end()) {
            impl_->active_pipes.erase(it);
          }
        }
        impl_->clients_cv.notify_all();

        CoUninitialize();
      });

      {
        std::lock_guard<std::mutex> clients_lock(impl_->clients_mutex);
        impl_->client_threads.push_back(std::move(client_worker));
      }
    }

    if (!signaled_ready && ready_event != NULL) {
      SetEvent(ready_event);
    }

    impl_->running.store(false);
  });

  if (ready_event != NULL) {
    WaitForSingleObject(ready_event, 2000);
    CloseHandle(ready_event);
  }

  return true;
}

void PipeServer::Stop() {
  std::lock_guard<std::mutex> lock(impl_->mutex);

  if (!impl_->running.load() && impl_->stop_event == NULL) {
    return;
  }

  impl_->stop_requested.store(true);

  if (impl_->stop_event != NULL) {
    SetEvent(impl_->stop_event);
  }

  // Cancel I/O and disconnect active pipe instances to unblock worker loops
  {
    std::lock_guard<std::mutex> clients_lock(impl_->clients_mutex);
    for (HANDLE pipe : impl_->active_pipes) {
      if (pipe != INVALID_HANDLE_VALUE && pipe != NULL) {
        CancelIo(pipe);
        DisconnectNamedPipe(pipe);
      }
    }
  }

  if (impl_->listener_thread.joinable()) {
    impl_->listener_thread.join();
  }

  // Join all client threads safely
  {
    std::lock_guard<std::mutex> clients_lock(impl_->clients_mutex);
    for (auto& th : impl_->client_threads) {
      if (th.joinable()) {
        th.join();
      }
    }
    impl_->client_threads.clear();
    impl_->active_pipes.clear();
  }

  if (impl_->stop_event != NULL) {
    CloseHandle(impl_->stop_event);
    impl_->stop_event = NULL;
  }

  impl_->running.store(false);
}

bool PipeServer::IsRunning() const {
  return impl_->running.load();
}

const std::string& PipeServer::PipeName() const {
  return impl_->pipe_name;
}

}  // namespace dbgx::mcp
