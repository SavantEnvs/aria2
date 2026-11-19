// Netscape cookies.txt files, loaded by `aria2c --load-cookies=FILE`:
// CookieStorage::load -> NsCookieParser (tab-separated fields, domain/path/expiry
// parsing, Cookie construction) into the storage, then written back with saveNsFormat
// as --save-cookies does. (Built without SQLite, so the file always takes aria2's own
// parser rather than sqlite3's.)
#include "fuzz_common.h"

#include <string>

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
  std::string in = aria2fuzz::writeTemp(data, size, ".txt");
  if (in.empty()) {
    return 0;
  }
  try {
    CookieStorage st;
    if (st.load(in, 1700000000)) {
      st.criteriaFind("www.example.org", "/", 1700000001, false);
      st.saveNsFormat(in);
    }
  }
  catch (Exception& e) {
  }
  unlink(in.c_str());
  return 0;
}
