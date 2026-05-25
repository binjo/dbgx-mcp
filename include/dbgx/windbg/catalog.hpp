#pragma once

#include <string>
#include <vector>
#include <optional>

namespace dbgx::windbg {

struct CatalogEntry {
  std::string id;
  std::string title;
  std::string summary;
  std::vector<std::string> tokens;
  std::string syntax;
  std::string documentation;
};

class Catalog {
 public:
  static const std::vector<CatalogEntry>& GetEntries();
  static std::vector<CatalogEntry> Search(const std::string& query, size_t limit = 10);
  static std::optional<CatalogEntry> GetById(const std::string& id);
};

} // namespace dbgx::windbg
