// .aria2 control files: the resume state aria2 reads back from "<file>.aria2" next to
// a download (--continue, or any restart). DefaultBtProgressInfoFile::load parses the
// version 0000/0001 layout: info-hash check, piece length, total/upload length,
// bitfield, and the in-flight pieces with their own bitfields, restoring them into
// the download's DefaultPieceStorage.
// Byte 0 picks the download it is loaded for (as the real file sits next to either
// kind): odd = a BitTorrent download (info hash 11 22 33 .. ff 00 ff ff ff ff,
// 1 KiB pieces, 80 KiB), even = an HTTP/FTP download (1 KiB pieces, 80 KiB).
#include "fuzz_common.h"

#include <memory>
#include <string>

#include "BtRuntime.h"
#include "DefaultBtProgressInfoFile.h"
#include "DefaultPeerStorage.h"
#include "DefaultPieceStorage.h"
#include "DownloadContext.h"
#include "Exception.h"
#include "FileEntry.h"
#include "Option.h"
#include "TorrentAttribute.h"
#include "a2functional.h"
#include "bittorrent_helper.h"
#include "prefs.h"

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
  const bool bt = data[0] & 1;
  std::string path = aria2fuzz::writeTemp(data + 1, size - 1, ".aria2");
  if (path.empty()) {
    return 0;
  }
  const std::string base = path.substr(0, path.size() - 6);
  const int32_t pieceLength = 1024;
  const int64_t totalLength = 80 * 1024;

  auto option = std::make_shared<Option>();
  auto dctx = std::make_shared<DownloadContext>();
  if (bt) {
    static const unsigned char infoHash[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff,
    };
    auto attrs = make_unique<TorrentAttribute>();
    attrs->infoHash.assign(std::begin(infoHash), std::end(infoHash));
    dctx->setAttribute(CTX_ATTR_BT, std::move(attrs));
  }
  const std::shared_ptr<FileEntry> fileEntries[] = {
      std::make_shared<FileEntry>(base, totalLength, 0)};
  dctx->setFileEntries(std::begin(fileEntries), std::end(fileEntries));
  dctx->setPieceLength(pieceLength);
  dctx->setBasePath(base);

  auto pieceStorage = std::make_shared<DefaultPieceStorage>(dctx, option.get());
  auto peerStorage = std::make_shared<DefaultPeerStorage>();
  auto btRuntime = std::make_shared<BtRuntime>();
  try {
    DefaultBtProgressInfoFile infoFile(dctx, pieceStorage, option.get());
    if (bt) {
      infoFile.setBtRuntime(btRuntime);
      infoFile.setPeerStorage(peerStorage);
    }
    infoFile.load();
  }
  catch (Exception& e) {
  }
  unlink(path.c_str());
  return 0;
}
