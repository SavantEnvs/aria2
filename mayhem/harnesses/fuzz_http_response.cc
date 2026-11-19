// HTTP from the wire. Byte 0 picks the side aria2 is on:
//  * even: aria2 the HTTP client (HttpConnection / HttpResponseCommand). The rest is a
//    server's response: HttpHeaderProcessor(CLIENT_PARSER) parses the header block, then
//    HttpResponse validates it (status, Content-Range), derives the file name from
//    Content-Disposition, stores Set-Cookie into a CookieStorage, reads Link/Digest
//    (Metalink/HTTP) and Location; whatever follows the header block is the body, decoded
//    through the Transfer-Encoding (chunked) and Content-Encoding (gzip/deflate) filter
//    chain HttpResponseCommand builds.
//  * odd: aria2 the RPC/WebSocket server (HttpServer::receiveRequest). The rest is a
//    client's request header, parsed by HttpHeaderProcessor(SERVER_PARSER), then the
//    fields HttpServer reads (Content-Length, Accept-Encoding, Authorization, Origin).
// The low bits of byte 1 split the header into incremental parse() calls, as bytes
// arriving from a socket would be.
#include "fuzz_common.h"

#include <memory>
#include <vector>

#include "ByteArrayDiskWriter.h"
#include "Checksum.h"
#include "CookieStorage.h"
#include "Exception.h"
#include "FileEntry.h"
#include "HttpHeader.h"
#include "HttpHeaderProcessor.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "MetalinkHttpEntry.h"
#include "Option.h"
#include "Piece.h"
#include "PiecedSegment.h"
#include "Range.h"
#include "Request.h"
#include "SinkStreamFilter.h"
#include "StreamFilter.h"
#include "a2functional.h"
#include "base64.h"
#include "util.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

namespace {

using namespace aria2;

// Returns the parsed header, and in |consumed| the number of input bytes the header
// block took; nullptr if the header never completed.
std::unique_ptr<HttpHeader> parseHeader(HttpHeaderProcessor& proc,
                                        const uint8_t* data, size_t size,
                                        size_t step, size_t& consumed)
{
  size_t off = 0;
  while (off < size) {
    size_t n = std::min(step, size - off);
    if (proc.parse(data + off, n)) {
      consumed = off + proc.getLastBytesProcessed();
      return proc.getResult();
    }
    off += n;
  }
  return nullptr;
}

void clientSide(const uint8_t* data, size_t size, size_t step)
{
  HttpHeaderProcessor proc(HttpHeaderProcessor::CLIENT_PARSER);
  size_t consumed = 0;
  auto header = parseHeader(proc, data, size, step, consumed);
  if (!header) {
    return;
  }
  header->getRange();

  CookieStorage cookies;
  auto option = std::make_shared<Option>();
  auto httpRequest = make_unique<HttpRequest>();
  auto request = std::make_shared<Request>();
  request->setUri("http://www.example.org/dir/file.bin");
  httpRequest->setRequest(request);
  auto piece = std::make_shared<Piece>(1, 1024 * 1024);
  httpRequest->setSegment(std::make_shared<PiecedSegment>(1024 * 1024, piece));
  httpRequest->setFileEntry(
      std::make_shared<FileEntry>("file.bin", 10 * 1024 * 1024, 0));
  httpRequest->setCookieStorage(&cookies);
  httpRequest->setOption(option.get());

  HttpResponse res;
  res.setHttpRequest(std::move(httpRequest));
  res.setHttpHeader(std::move(header));

  try {
    res.validateResponse();
  }
  catch (Exception& e) {
  }
  res.determineFilename(true);
  res.determineFilename(false);
  res.retrieveCookie();
  cookies.criteriaFind("www.example.org", "/dir/", 1700000000, false);
  res.getContentLength();
  res.getEntityLength();
  res.getContentType();
  res.getLastModifiedTime();
  res.supportsPersistentConnection();
  {
    std::vector<MetalinkHttpEntry> links;
    res.getMetalinKHttpEntries(links, option);
    std::vector<Checksum> digests;
    res.getDigest(digests);
  }
  if (res.isRedirect()) {
    try {
      res.processRedirect();
    }
    catch (Exception& e) {
    }
  }

  // Body: build the same filter chain HttpResponseCommand does
  // (transfer-encoding -> content-encoding -> sink) and push the rest through it.
  std::unique_ptr<StreamFilter> filter = make_unique<SinkStreamFilter>();
  filter->init();
  if (res.isContentEncodingSpecified()) {
    auto ce = res.getContentEncodingStreamFilter();
    if (ce) {
      ce->init();
      ce->installDelegate(std::move(filter));
      filter = std::move(ce);
    }
  }
  if (res.isTransferEncodingSpecified()) {
    auto te = res.getTransferEncodingStreamFilter();
    if (!te) {
      return; // aria2 aborts: unsupported Transfer-Encoding
    }
    te->init();
    te->installDelegate(std::move(filter));
    filter = std::move(te);
  }
  auto out = std::make_shared<ByteArrayDiskWriter>();
  auto segment =
      std::make_shared<PiecedSegment>(1024 * 1024, std::make_shared<Piece>(0, 1024 * 1024));
  size_t off = consumed;
  while (off < size && !filter->finished()) {
    size_t n = std::min(step, size - off);
    filter->transform(out, segment, data + off, n);
    off += n;
  }
  filter->release();
}

void serverSide(const uint8_t* data, size_t size, size_t step)
{
  HttpHeaderProcessor proc(HttpHeaderProcessor::SERVER_PARSER);
  size_t consumed = 0;
  auto header = parseHeader(proc, data, size, step, consumed);
  if (!header) {
    return;
  }
  header->getMethod();
  header->getRequestPath();
  header->isKeepAlive();
  int64_t len;
  util::parseLLIntNoThrow(len, header->find(HttpHeader::CONTENT_LENGTH));
  const std::string& acceptEnc = header->find(HttpHeader::ACCEPT_ENCODING);
  std::vector<Scip> encs;
  util::splitIter(acceptEnc.begin(), acceptEnc.end(), std::back_inserter(encs),
                  ',', true);
  const std::string& auth = header->find(HttpHeader::AUTHORIZATION);
  if (util::startsWith(auth, "Basic ")) {
    base64::decode(auth.begin() + 6, auth.end());
  }
  header->findAll(HttpHeader::ORIGIN);
  header->fieldContains(HttpHeader::UPGRADE, "websocket");
  header->fieldContains(HttpHeader::CONNECTION, "upgrade");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 2) {
    return -1;
  }
  bool server = data[0] & 1;
  size_t step = (data[1] & 0x3f) == 0 ? size : (data[1] & 0x3f);
  try {
    if (server) {
      serverSide(data + 2, size - 2, step);
    }
    else {
      clientSide(data + 2, size - 2, step);
    }
  }
  catch (Exception& e) {
  }
  return 0;
}
