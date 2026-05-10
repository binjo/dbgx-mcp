#pragma once

#include <windows.h>
#include <DbgEng.h>

#include <DbgModel.h>
#include <wrl/client.h>

#include <string>

#include "dbgx/mcp/json_writer.hpp"

namespace dbgx::windbg {

/**
 * Utility to serialize a WinDbg Data Model object (IModelObject) into structured JSON.
 * 
 * This handles:
 * - Primitives (integers, booleans, strings)
 * - Synthetic objects (recursive key-value iteration)
 * - Iterables (arrays and collections)
 * - Fallback to display strings (IStringDisplayableConcept)
 */
class ModelSerializer {
 public:
  static void Serialize(IModelObject* object, mcp::JsonWriter& writer, int max_depth = 5);

 private:
  static void SerializeRecursive(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth);
  static void SerializeIntrinsic(
      IModelObject* object, const VARIANT& vt, mcp::JsonWriter& writer, int current_depth, int max_depth);
  static bool TrySerializeIterable(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth);
  static bool TrySerializeKeys(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth);
  static void SerializeDisplayString(IModelObject* object, mcp::JsonWriter& writer);
};

}  // namespace dbgx::windbg
