// BitTorrent peer-wire bytes from a remote peer. The first 68 bytes are the handshake
// (DefaultBtMessageFactory::createHandshakeMessage + its validator: protocol string,
// reserved bits, info-hash); the rest is the length-prefixed message stream
// PeerConnection::receiveMessage frames (4-byte big-endian length, capped at
// MAX_BUFFER_CAPACITY like aria2), each payload going through
// DefaultBtMessageFactory::createBtMessage and validate() as DefaultBtMessageReceiver
// does: choke/have/bitfield/request/piece/cancel/port/fast-extension messages and the
// extended (id 20) messages, which the real DefaultExtensionMessageFactory parses
// (extension handshake, ut_pex compact peer lists, ut_metadata).
// The download is a small single-file torrent loaded once per input; the peer has
// ut_pex=1 and ut_metadata=2 registered.
#include "fuzz_common.h"

#include <memory>
#include <string>

#include "BtHandshakeMessage.h"
#include "BtMessage.h"
#include "BtRuntime.h"
#include "DefaultBtMessageFactory.h"
#include "DefaultExtensionMessageFactory.h"
#include "DefaultPeerStorage.h"
#include "DefaultPieceStorage.h"
#include "DownloadContext.h"
#include "Exception.h"
#include "ExtensionMessageRegistry.h"
#include "GroupId.h"
#include "Option.h"
#include "Peer.h"
#include "PeerConnection.h"
#include "RequestGroup.h"
#include "UTMetadataRequestTracker.h"
#include "bittorrent_helper.h"

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  aria2fuzz::quietInit();
  return 0;
}

namespace {
// 4 pieces of 16 KiB, single file.
std::string torrent()
{
  return "d4:infod6:lengthi65536e4:name8:file.bin12:piece lengthi16384e"
         "6:pieces80:" +
         std::string(80, 'P') + "ee";
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using namespace aria2;
  if (size < 68) {
    return -1;
  }
  auto option = std::make_shared<Option>();
  auto dctx = std::make_shared<DownloadContext>();
  bittorrent::loadFromMemory(torrent(), dctx, option, "default");
  RequestGroup group(GroupId::create(), option);
  group.setDownloadContext(dctx);
  DefaultPieceStorage pieceStorage(dctx, option.get());
  DefaultPeerStorage peerStorage;
  auto peer = std::make_shared<Peer>("192.168.0.1", 6881);
  peer->allocateSessionResource(dctx->getPieceLength(),
                                dctx->getTotalLength());
  peer->setExtendedMessagingEnabled(true);
  peer->setFastExtensionEnabled(true);
  peer->setExtension(ExtensionMessageRegistry::UT_PEX, 1);
  peer->setExtension(ExtensionMessageRegistry::UT_METADATA, 2);

  ExtensionMessageRegistry registry;
  registry.setExtensionMessageID(ExtensionMessageRegistry::UT_PEX, 1);
  registry.setExtensionMessageID(ExtensionMessageRegistry::UT_METADATA, 2);
  UTMetadataRequestTracker utTracker;
  DefaultExtensionMessageFactory exFactory(peer, &registry);
  exFactory.setPeerStorage(&peerStorage);
  exFactory.setDownloadContext(dctx.get());
  exFactory.setUTMetadataRequestTracker(&utTracker);

  DefaultBtMessageFactory factory;
  factory.setDownloadContext(dctx.get());
  factory.setPieceStorage(&pieceStorage);
  factory.setPeerStorage(&peerStorage);
  factory.setPeer(peer);
  factory.setExtensionMessageFactory(&exFactory);
  exFactory.setBtMessageFactory(&factory);

  try {
    auto hs = factory.createHandshakeMessage(data, 68);
    hs->validate();
    hs->toString();
  }
  catch (Exception& e) {
  }

  size_t off = 68;
  while (off + 4 <= size) {
    uint32_t len = (uint32_t(data[off]) << 24) | (uint32_t(data[off + 1]) << 16) |
                   (uint32_t(data[off + 2]) << 8) | uint32_t(data[off + 3]);
    off += 4;
    if (len + 4 > MAX_BUFFER_CAPACITY || len > size - off) {
      break; // aria2 drops the peer (too long) or waits for more bytes
    }
    try {
      auto msg = factory.createBtMessage(data + off, len);
      msg->validate();
      msg->toString();
    }
    catch (Exception& e) {
    }
    off += len;
  }
  return 0;
}
