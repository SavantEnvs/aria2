// The aria2c command line on an untrusted file: `aria2c --no-conf -S FILE`
// (--show-files), run through aria2::Context, the same option processing and
// dispatch aria2c's main() and libaria2's sessionNew use. ProtocolDetector sniffs
// the file and hands it to the torrent loader (bittorrent::load + print) or the
// Metalink parser (metalink::parseAndQuery + file listing).
// Context is created with standalone=false (the libaria2 mode): an option error
// throws instead of calling exit(); the fixed argument list never triggers one.
#include "fuzz_common.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "Context.h"
#include "Exception.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  std::string path = aria2fuzz::writeTemp(data, size, ".bin");
  if (path.empty()) {
    return 0;
  }
  std::vector<std::string> args = {"aria2c", "--no-conf", "--show-files",
                                   path};
  std::vector<char*> argv;
  for (auto& a : args) {
    argv.push_back(&a[0]);
  }
  argv.push_back(nullptr);
  optind = 0; // getopt_long state is per process; re-initialise it per run
  try {
    Context ctx(false, static_cast<int>(args.size()), argv.data(), KeyVals());
  }
  catch (Exception& e) {
  }
  unlink(path.c_str());
  return 0;
}
