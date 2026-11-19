// URIs and magnet links as they reach aria2 from the command line, -i input files,
// RPC aria2.addUri, HTTP Location headers and Metalink/torrent url-lists.
// The input is "<base>\n<uri>" (no newline: the whole input is the URI):
// uri::parse (uri_split.c state machine, percent-decoding, IPv6 literals),
// uri::construct, uri::joinUri against the base (relative reference resolution and
// path normalisation, what aria2 does with a redirect Location), and for magnet:
// links bittorrent::parseMagnet (magnet::parse, xt=urn:btih hex/base32 info-hash,
// tr/dn) followed by torrent2Magnet.
#include "fuzz_common.h"

#include <string>

#include "Exception.h"
#include "bittorrent_helper.h"
#include "uri.h"
#include "util.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  std::string in(reinterpret_cast<const char*>(data), size);
  std::string base = "http://example.org/a/b/c?q=1";
  std::string s = in;
  size_t nl = in.find('\n');
  if (nl != std::string::npos) {
    base = in.substr(0, nl);
    s = in.substr(nl + 1);
  }
  uri::UriStruct us;
  if (uri::parse(us, s)) {
    uri::construct(us);
  }
  uri::joinUri(base, s);
  util::percentDecode(s.begin(), s.end());
  try {
    auto attrs = bittorrent::parseMagnet(s);
    if (attrs) {
      bittorrent::torrent2Magnet(attrs.get());
    }
  }
  catch (Exception& e) {
  }
  return 0;
}
