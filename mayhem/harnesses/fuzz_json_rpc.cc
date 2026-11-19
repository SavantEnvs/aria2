// JSON-RPC requests as aria2's RPC server (HttpServerBodyCommand) receives them.
// Byte 0 picks the transport:
//  * even: a POST body, parsed by json::ValueBaseJsonParser (JsonParser +
//    ValueBaseStructParserStateMachine);
//  * odd: a GET query string ("method=..&id=..&params=<base64>&jsoncallback=.."),
//    unpacked by json::decodeGetParams and then parsed the same way.
// The parsed value is then encoded back the way responses are sent: rpc::toJson /
// toJsonBatch (JSON and JSONP) with and without gzip (GZipEncoder, fixed upstream in
// 42038422f6), rpc::toXml, and json::encode.
#include "fuzz_common.h"

#include <memory>
#include <string>
#include <vector>

#include "Exception.h"
#include "RpcResponse.h"
#include "ValueBase.h"
#include "ValueBaseJsonParser.h"
#include "json.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  if (size < 1) {
    return -1;
  }
  bool get = data[0] & 1;
  std::string body(reinterpret_cast<const char*>(data + 1), size - 1);
  std::string callback;
  try {
    if (get) {
      json::JsonGetParam param = json::decodeGetParams(body);
      body = param.request;
      callback = param.callback;
    }
    ssize_t error = 0;
    auto value = json::ValueBaseJsonParser().parseFinal(body.data(),
                                                        body.size(), error);
    if (error < 0 || !value) {
      return 0;
    }
    json::encode(value.get());
    if (auto list = downcast<List>(value)) {
      std::vector<rpc::RpcResponse> batch;
      int64_t n = 0;
      for (auto& v : *list) {
        batch.emplace_back(0, rpc::RpcResponse::AUTHORIZED, std::move(v),
                           Integer::g(n++));
      }
      rpc::toJsonBatch(batch, callback, false);
      rpc::toJsonBatch(batch, callback, true);
    }
    else {
      rpc::RpcResponse res(1, rpc::RpcResponse::AUTHORIZED, std::move(value),
                           String::g("fuzz-id"));
      rpc::toJson(res, callback, false);
      rpc::toJson(res, callback, true);
      rpc::toXml(res, false);
      rpc::toXml(res, true);
    }
  }
  catch (Exception& e) {
  }
  return 0;
}
