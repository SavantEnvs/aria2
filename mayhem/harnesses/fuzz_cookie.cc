// Set-Cookie header values (cookie_helper.cc: cookie::parse / cookie::parseDate,
// the code upstream fixed in e5d9ad2f0b) as aria2 stores them: the input is
// "<request-host>\n<request-path>\n<Set-Cookie value>[\n<Set-Cookie value>...]".
// Each value goes through CookieStorage::parseAndStore (parse, domain/path
// checks, storage domain tree); then the stored cookies are matched back with
// criteriaFind for the request host/path, as HttpRequest does for the next request,
// and written out as a Netscape cookies.txt.
#include "fuzz_common.h"

#include <string>
#include <vector>

#include "Cookie.h"
#include "CookieStorage.h"
#include "Exception.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  std::string in(reinterpret_cast<const char*>(data), size);
  std::vector<std::string> lines;
  size_t start = 0;
  for (;;) {
    size_t nl = in.find('\n', start);
    lines.push_back(in.substr(start, nl == std::string::npos ? std::string::npos
                                                             : nl - start));
    if (nl == std::string::npos) {
      break;
    }
    start = nl + 1;
  }
  if (lines.size() < 3) {
    return -1;
  }
  const std::string& host = lines[0];
  const std::string& path = lines[1];
  const time_t now = 1700000000;
  try {
    CookieStorage st;
    for (size_t i = 2; i < lines.size(); ++i) {
      st.parseAndStore(lines[i], host, path, now);
    }
    for (const Cookie* c : st.criteriaFind(host, path, now + 1, false)) {
      c->toString();
    }
    st.criteriaFind(host, path, now + 1, true);
    std::string out = aria2fuzz::writeTemp(nullptr, 0, ".txt");
    if (!out.empty()) {
      st.saveNsFormat(out);
      unlink(out.c_str());
    }
  }
  catch (Exception& e) {
  }
  return 0;
}
