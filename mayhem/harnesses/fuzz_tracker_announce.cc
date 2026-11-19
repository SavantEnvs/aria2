// HTTP tracker announce responses: the body a BitTorrent HTTP tracker returns, as
// HTTPAnnRequest::processResponse (src/TrackerWatcherCommand.cc) hands it to
// DefaultBtAnnounce::processAnnounceResponse. Any tracker URL in a .torrent or magnet
// controls this body. The response is bencode-decoded, then failure reason, warning
// message, tracker id, interval / min interval, complete / incomplete and the peer
// lists are read: compact "peers" / "peers6" strings and the dict-list form
// (d2:ip..4:porti..ee), both through bittorrent::extractPeer into a DefaultPeerStorage.
// Afterwards the announce scheduler reads the tracker-supplied intervals the way
// TrackerWatcherCommand does on its next tick (announceSuccess / announceFailure, then
// isDefaultAnnounceReady, which compares the min interval against the announce timer).
//
// Everything below is created per input; the setup mirrors
// test/DefaultBtAnnounceTest.cc (a 4 MiB, 256 KiB-piece BT download with a fixed info
// hash and peer id, one announce tier).
#include "fuzz_common.h"

#include <memory>

#include "BtRuntime.h"
#include "DefaultBtAnnounce.h"
#include "DefaultPeerStorage.h"
#include "DownloadContext.h"
#include "Exception.h"
#include "Option.h"
#include "bittorrent_helper.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  aria2::bittorrent::setStaticPeerId("-aria2-ultrafastdltl");
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  static const unsigned char infoHash[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
      0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67};

  Option option;
  DownloadContext dctx(256 * 1024, 4 * 1024 * 1024);
  {
    auto attrs = make_unique<TorrentAttribute>();
    attrs->infoHash.assign(std::begin(infoHash), std::end(infoHash));
    attrs->announceList.push_back({"http://tracker.example/announce"});
    dctx.setAttribute(CTX_ATTR_BT, std::move(attrs));
  }
  auto btRuntime = std::make_shared<BtRuntime>();
  auto peerStorage = std::make_shared<DefaultPeerStorage>();
  peerStorage->setBtRuntime(btRuntime);

  DefaultBtAnnounce an(&dctx, &option);
  an.setPeerStorage(peerStorage);
  an.setBtRuntime(btRuntime);
  try {
    an.processAnnounceResponse(data, size);
    an.announceSuccess();
  }
  catch (RecoverableException& e) {
    // malformed body or "failure reason": aria2 logs it and marks the tracker failed
    an.announceFailure();
  }
  an.isDefaultAnnounceReady();
  return 0;
}
