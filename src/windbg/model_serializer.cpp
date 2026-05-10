#include "dbgx/windbg/model_serializer.hpp"

#include <windows.h>
#include <wrl/client.h>

#include <string>

using namespace Microsoft::WRL;

namespace dbgx::windbg {

namespace {

std::string WideToUtf8(std::wstring_view wide) {
  if (wide.empty()) return "";
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), NULL, 0, NULL, NULL);
  std::string strTo(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), &strTo[0], size_needed, NULL, NULL);
  return strTo;
}

}  // namespace

void ModelSerializer::Serialize(IModelObject* object, mcp::JsonWriter& writer, int max_depth) {
  SerializeRecursive(object, writer, 0, max_depth);
}

void ModelSerializer::SerializeRecursive(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth) {
  if (object == nullptr) {
    writer.NullValue();
    return;
  }

  if (current_depth >= max_depth) {
    SerializeDisplayString(object, writer);
    return;
  }

  VARIANT vt;
  VariantInit(&vt);
  if (SUCCEEDED(object->GetIntrinsicValue(&vt))) {
    SerializeIntrinsic(object, vt, writer, current_depth, max_depth);
    VariantClear(&vt);
    return;
  }

  // Attempt to serialize as a collection/array
  if (TrySerializeIterable(object, writer, current_depth, max_depth)) {
    return;
  }

  // Attempt to serialize as an object with properties/keys
  if (TrySerializeKeys(object, writer, current_depth, max_depth)) {
    return;
  }

  // Fallback to display string
  SerializeDisplayString(object, writer);
}

void ModelSerializer::SerializeIntrinsic(IModelObject* object, const VARIANT& vt, mcp::JsonWriter& writer, int current_depth, int max_depth) {
  switch (vt.vt) {
    case VT_BSTR:
      writer.StringValue(WideToUtf8(vt.bstrVal ? vt.bstrVal : L""));
      break;
    case VT_BOOL:
      writer.BoolValue(vt.boolVal != VARIANT_FALSE);
      break;
    case VT_I1:
    case VT_I2:
    case VT_I4:
    case VT_I8:
    case VT_INT: {
      VARIANT vt_i8;
      if (SUCCEEDED(VariantChangeType(&vt_i8, &vt, 0, VT_I8))) {
        writer.IntValue(vt_i8.llVal);
      } else {
        writer.NullValue();
      }
      break;
    }
    case VT_UI1:
    case VT_UI2:
    case VT_UI4:
    case VT_UI8:
    case VT_UINT: {
      VARIANT vt_ui8;
      if (SUCCEEDED(VariantChangeType(&vt_ui8, &vt, 0, VT_UI8))) {
        // Many WinDbg numbers (addresses/handles) are best represented as hex strings for agents
        writer.HexValue(vt_ui8.ullVal);
      } else {
        writer.NullValue();
      }
      break;
    }
    case VT_EMPTY:
    case VT_NULL:
      writer.NullValue();
      break;
    default:
      SerializeDisplayString(object, writer);
      break;
  }
}

bool ModelSerializer::TrySerializeIterable(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth) {
  ComPtr<IIterableConcept> iter_concept;
  if (FAILED(object->GetConcept(__uuidof(IIterableConcept), &iter_concept, nullptr))) {
    return false;
  }

  ComPtr<IModelIterator> iterator;
  if (FAILED(iter_concept->GetIterator(object, &iterator))) {
    return false;
  }

  writer.StartArray();
  ComPtr<IModelObject> item;
  while (SUCCEEDED(iterator->GetNext(&item, 0, nullptr, nullptr)) && item) {
    SerializeRecursive(item.Get(), writer, current_depth + 1, max_depth);
    item.Reset();
  }
  writer.EndArray();
  return true;
}

bool ModelSerializer::TrySerializeKeys(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth) {
  ComPtr<IKeyEnumerator> keys;
  // Use EnumerateKeyValues to get the actual property values rather than just names
  if (FAILED(object->EnumerateKeyValues(&keys))) {
    return false;
  }

  bool found_keys = false;
  BSTR key_name = nullptr;
  ComPtr<IModelObject> key_value;

  while (SUCCEEDED(keys->GetNext(&key_name, &key_value, nullptr)) && key_name) {
    if (!found_keys) {
      writer.StartObject();
      found_keys = true;
    }

    writer.Key(WideToUtf8(key_name));
    SerializeRecursive(key_value.Get(), writer, current_depth + 1, max_depth);

    SysFreeString(key_name);
    key_name = nullptr;
    key_value.Reset();
  }

  if (found_keys) {
    writer.EndObject();
  }
  return found_keys;
}

void ModelSerializer::SerializeDisplayString(IModelObject* object, mcp::JsonWriter& writer) {
  ComPtr<IStringDisplayableConcept> display_concept;
  if (SUCCEEDED(object->GetConcept(__uuidof(IStringDisplayableConcept), &display_concept, nullptr))) {
    BSTR display_str = nullptr;
    if (SUCCEEDED(display_concept->ToDisplayString(object, nullptr, &display_str))) {
      writer.StringValue(WideToUtf8(display_str ? display_str : L""));
      if (display_str) SysFreeString(display_str);
      return;
    }
  }

  // Absolute fallback
  writer.StringValue("<object>");
}

}  // namespace dbgx::windbg