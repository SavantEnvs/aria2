// The -i/--input-file list (`aria2c -i FILE`): run through aria2::Context with
// `--no-conf --dry-run -i FILE`, which builds the download queue without starting it.
// UriListParser reads the URI lines (tab-separated mirrors) and the indented
// per-download option lines, which go through OptionParser and every OptionHandler's
// value parser (sizes, ranges, header lists, proxies, checksums, index-out, ...);
// then the request groups are created for the URIs (uri parsing, protocol
// detection, magnet links, local .torrent/.metalink paths).
// Context is created with standalone=false (the libaria2 mode): an option error
// throws instead of calling exit().
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
  std::string path = aria2fuzz::writeTemp(data, size, ".txt");
  if (path.empty()) {
    return 0;
  }
  std::vector<std::string> args = {"aria2c", "--no-conf", "--quiet",
                                   "--dry-run", "-i", path};
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
