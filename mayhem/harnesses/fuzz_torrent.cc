// .torrent metainfo: what `aria2c -T file` / RPC aria2.addTorrent hand to
// bittorrent::loadFromMemory (bencode2 decoder, info dict / files / announce-list /
// url-list extraction, path sanitising), then the `--show-files` listing and the
// magnet URI aria2 derives from the loaded torrent.
#include "fuzz_common.h"

#include <memory>

#include "DownloadContext.h"
#include "Exception.h"
#include "FileEntry.h"
#include "NullOutputFile.h"
#include "Option.h"
#include "bittorrent_helper.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  auto option = std::make_shared<Option>();
  auto dctx = std::make_shared<DownloadContext>();
  try {
    bittorrent::loadFromMemory(data, size, dctx, option, "default");
    NullOutputFile out;
    bittorrent::print(out, dctx);
    bittorrent::torrent2Magnet(bittorrent::getTorrentAttrs(dctx));
  }
  catch (Exception& e) {
    // malformed torrent: aria2 reports it and moves on
  }
  return 0;
}
