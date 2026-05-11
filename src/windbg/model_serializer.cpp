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

HRESULT GetKindSafe(IModelObject* object, ModelObjectKind* kind) {
  __try {
    return object->GetKind(kind);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT GetIntrinsicValueSafe(IModelObject* object, VARIANT* vt) {
  __try {
    return object->GetIntrinsicValue(vt);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT GetConceptSafe(IModelObject* object, REFIID concept_id, void** concept_interface) {
  __try {
    return object->GetConcept(concept_id, reinterpret_cast<IUnknown**>(concept_interface), nullptr);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT ToDisplayStringSafe(IStringDisplayableConcept* display_concept, IModelObject* object, BSTR* display_str) {
  __try {
    return display_concept->ToDisplayString(object, nullptr, display_str);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT GetIteratorSafe(IIterableConcept* iter_concept, IModelObject* object, IModelIterator** iterator) {
  __try {
    return iter_concept->GetIterator(object, iterator);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT GetNextItemSafe(IModelIterator* iterator, IModelObject** item) {
  __try {
    return iterator->GetNext(item, 0, nullptr, nullptr);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT EnumerateKeyValuesSafe(IModelObject* object, IKeyEnumerator** keys) {
  __try {
    return object->EnumerateKeyValues(keys);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
}

HRESULT GetNextKeySafe(IKeyEnumerator* keys, BSTR* key_name, IModelObject** key_value) {
  __try {
    return keys->GetNext(key_name, key_value, nullptr);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return E_FAIL;
  }
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

  ModelObjectKind kind = ObjectNoValue;
  if (FAILED(GetKindSafe(object, &kind))) {
    SerializeDisplayString(object, writer);
    return;
  }

  if (kind == ObjectError) {
    SerializeDisplayString(object, writer);
    return;
  }

  if (kind == ObjectNoValue) {
    writer.NullValue();
    return;
  }

  if (kind == ObjectMethod || kind == ObjectPropertyAccessor || kind == ObjectContext) {
    SerializeDisplayString(object, writer);
    return;
  }

  if (kind == ObjectIntrinsic) {
    VARIANT vt;
    VariantInit(&vt);
    if (SUCCEEDED(GetIntrinsicValueSafe(object, &vt))) {
      SerializeIntrinsic(object, vt, writer, current_depth, max_depth);
      VariantClear(&vt);
    } else {
      SerializeDisplayString(object, writer);
    }
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
  if (FAILED(GetConceptSafe(object, __uuidof(IIterableConcept), &iter_concept))) {
    return false;
  }

  ComPtr<IModelIterator> iterator;
  if (FAILED(GetIteratorSafe(iter_concept.Get(), object, &iterator))) {
    return false;
  }

  writer.StartArray();
  ComPtr<IModelObject> item;
  while (SUCCEEDED(GetNextItemSafe(iterator.Get(), &item)) && item) {
    SerializeRecursive(item.Get(), writer, current_depth + 1, max_depth);
    item.Reset();
  }
  writer.EndArray();
  return true;
}

bool ModelSerializer::TrySerializeKeys(IModelObject* object, mcp::JsonWriter& writer, int current_depth, int max_depth) {
  ComPtr<IKeyEnumerator> keys;
  // Use EnumerateKeyValuesSafe to get the actual property values rather than just names
  if (FAILED(EnumerateKeyValuesSafe(object, &keys))) {
    return false;
  }

  bool found_keys = false;
  BSTR key_name = nullptr;
  ComPtr<IModelObject> key_value;

  while (SUCCEEDED(GetNextKeySafe(keys.Get(), &key_name, &key_value)) && key_name) {
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
  if (object == nullptr) {
    writer.NullValue();
    return;
  }

  ModelObjectKind kind = ObjectNoValue;
  if (FAILED(GetKindSafe(object, &kind))) {
    writer.StringValue("<object>");
    return;
  }

  if (kind == ObjectError) {
    writer.StringValue("<error>");
    return;
  }
  if (kind == ObjectNoValue) {
    writer.NullValue();
    return;
  }
  if (kind == ObjectMethod) {
    writer.StringValue("<method>");
    return;
  }
  if (kind == ObjectPropertyAccessor) {
    writer.StringValue("<property accessor>");
    return;
  }
  if (kind == ObjectContext) {
    writer.StringValue("<context>");
    return;
  }

  ComPtr<IStringDisplayableConcept> display_concept;
  if (SUCCEEDED(GetConceptSafe(object, __uuidof(IStringDisplayableConcept), &display_concept))) {
    BSTR display_str = nullptr;
    if (SUCCEEDED(ToDisplayStringSafe(display_concept.Get(), object, &display_str))) {
      writer.StringValue(WideToUtf8(display_str ? display_str : L""));
      if (display_str) SysFreeString(display_str);
      return;
    }
  }

  // Absolute fallback
  writer.StringValue("<object>");
}

}  // namespace dbgx::windbg