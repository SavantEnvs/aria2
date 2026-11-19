// Metalink v3 (.metalink) / v4 (.meta4) documents: what `aria2c -M file` and RPC
// aria2.addMetalink parse. metalink::parseAndQuery runs the expat SAX parser,
// the v3+v4 MetalinkParserStateMachine and the version/language/OS query, and
// MetalinkEntry::toFileEntry builds the file list aria2 downloads.
#include "fuzz_common.h"

#include <memory>

#include "ByteArrayDiskWriter.h"
#include "Exception.h"
#include "FileEntry.h"
#include "MetalinkEntry.h"
#include "Metalinker.h"
#include "Option.h"
#include "metalink_helper.h"
#include "prefs.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  ByteArrayDiskWriter dw;
  dw.setString(std::string(reinterpret_cast<const char*>(data), size));
  Option option;
  try {
    auto entries =
        metalink::parseAndQuery(&dw, &option, "http://base.example/dir/");
    auto groups = metalink::groupEntryByMetaurlName(entries);
    (void)groups;
    auto fileEntries = MetalinkEntry::toFileEntry(std::move(entries));
    (void)fileEntries;
  }
  catch (Exception& e) {
  }
  return 0;
}
