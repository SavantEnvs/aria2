// XML-RPC requests as aria2's RPC server receives them on /rpc: rpc::xmlParseMemory
// runs the expat SAX parser through XmlRpcRequestParserStateMachine (methodCall,
// params, struct/array/base64/int/double/string values). The parsed parameters are
// then encoded back as a response (rpc::toXml, rpc::toJson, with and without gzip).
#include "fuzz_common.h"

#include <memory>

#include "Exception.h"
#include "RpcRequest.h"
#include "RpcResponse.h"
#include "ValueBase.h"
#include "rpc_helper.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  try {
    rpc::RpcRequest req =
        rpc::xmlParseMemory(reinterpret_cast<const char*>(data), size);
    rpc::RpcResponse res(0, rpc::RpcResponse::AUTHORIZED, std::move(req.params),
                         String::g(req.methodName));
    rpc::toXml(res, false);
    rpc::toXml(res, true);
    rpc::toJson(res, "", false);
  }
  catch (Exception& e) {
  }
  return 0;
}
