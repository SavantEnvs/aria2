// The BitTorrent UDP port: datagrams as DHTInteractionCommand::execute receives them.
// The input is a sequence of datagrams, each "<2-byte big-endian length><bytes>",
// all from 192.168.0.2:6881. Like DHTInteractionCommand, a datagram starting with 'd'
// is DHT (KRPC) and goes to DHTMessageReceiver::receiveMessage (bencode decode,
// query messages via DHTMessageFactoryImpl::createQueryMessage, replies matched to
// outstanding queries in DHTMessageTracker, validate + doReceivedAction: compact
// node/peer lists, tokens, routing-table updates); anything else is a UDP tracker
// (BEP 15) reply and goes to UDPTrackerClient::receiveReply (connect / announce /
// error replies, peer lists).
//
// Kept on purpose, rebuilt for every input: a local DHT node, routing table and the
// outstanding queries aria2 had sent to that peer (ping "pi", find_node "fn",
// get_peers "gp", announce_peer "ap" transaction IDs), and one UDP tracker announce in
// flight to that peer. A UDP tracker reply only matches if it echoes the random
// 32-bit transaction ID aria2 sent, which an on-path tracker sees but a fuzzer
// cannot guess; byte 0 of the input decides which sender the datagrams come from:
// bit 0 set = the on-path tracker (the harness echoes the current transaction ID
// into bytes 4..7, as that tracker would), clear = a blind sender (bytes as given).
#include "fuzz_common.h"

#include <array>
#include <cstring>
#include <memory>
#include <string>

#include "a2netcompat.h"

#include "BtRegistry.h"
#include "DHTConnectionImpl.h"
#include "DHTConstants.h"
#include "DHTFindNodeMessage.h"
#include "DHTGetPeersMessage.h"
#include "DHTAnnouncePeerMessage.h"
#include "DHTMessage.h"
#include "DHTMessageCallback.h"
#include "DHTMessageEntry.h"
#include "DHTMessageTrackerEntry.h"
#include "DHTMessageDispatcherImpl.h"
#include "DHTMessageFactoryImpl.h"
#include "DHTMessageReceiver.h"
#include "DHTMessageTracker.h"
#include "DHTNode.h"
#include "DHTPeerAnnounceStorage.h"
#include "DHTPingMessage.h"
#include "DHTRoutingTable.h"
#include "DHTTokenTracker.h"
#include "Exception.h"
#include "TimerA2.h"
#include "UDPTrackerClient.h"
#include "UDPTrackerRequest.h"
#include "wallclock.h"

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
  const bool onPathTracker = data[0] & 1;
  const std::string remoteAddr = "192.168.0.2";
  const uint16_t remotePort = 6881;

  unsigned char localId[DHT_ID_LENGTH];
  memset(localId, 0x11, sizeof(localId));
  unsigned char remoteId[DHT_ID_LENGTH];
  memset(remoteId, 0x22, sizeof(remoteId));
  unsigned char infoHash[DHT_ID_LENGTH];
  memset(infoHash, 0x33, sizeof(infoHash));

  auto localNode = std::make_shared<DHTNode>(localId);
  auto tracker = std::make_shared<DHTMessageTracker>();
  DHTRoutingTable routingTable(localNode);
  DHTMessageFactoryImpl factory(AF_INET);
  DHTMessageDispatcherImpl dispatcher(tracker);
  DHTMessageReceiver receiver(tracker);
  DHTPeerAnnounceStorage peerAnnounceStorage;
  DHTTokenTracker tokenTracker;
  BtRegistry btRegistry;
  DHTConnectionImpl connection(AF_INET);

  tracker->setRoutingTable(&routingTable);
  tracker->setMessageFactory(&factory);
  receiver.setMessageFactory(&factory);
  receiver.setRoutingTable(&routingTable);
  factory.setRoutingTable(&routingTable);
  factory.setConnection(&connection);
  factory.setMessageDispatcher(&dispatcher);
  factory.setPeerAnnounceStorage(&peerAnnounceStorage);
  factory.setTokenTracker(&tokenTracker);
  factory.setLocalNode(localNode);
  factory.setBtRegistry(&btRegistry);

  auto remoteNode = std::make_shared<DHTNode>(remoteId);
  remoteNode->setIPAddress(remoteAddr);
  remoteNode->setPort(remotePort);
  {
    const auto timeout = std::chrono::seconds(10);
    auto ping = factory.createPingMessage(remoteNode, "pi");
    tracker->addMessage(ping.get(), timeout);
    auto findNode = factory.createFindNodeMessage(remoteNode, infoHash, "fn");
    tracker->addMessage(findNode.get(), timeout);
    auto getPeers = factory.createGetPeersMessage(remoteNode, infoHash, "gp");
    tracker->addMessage(getPeers.get(), timeout);
    auto announce = factory.createAnnouncePeerMessage(remoteNode, infoHash,
                                                      6881, "token", "ap");
    tracker->addMessage(announce.get(), timeout);
  }

  UDPTrackerClient udpTracker;
  {
    auto req = std::make_shared<UDPTrackerRequest>();
    req->remoteAddr = remoteAddr;
    req->remotePort = remotePort;
    req->action = UDPT_ACT_ANNOUNCE;
    req->infohash = std::string(reinterpret_cast<char*>(infoHash), 20);
    req->peerId = std::string(20, 'p');
    req->downloaded = 0;
    req->left = 65536;
    req->uploaded = 0;
    req->event = UDPT_EVT_STARTED;
    req->ip = 0;
    req->key = 1;
    req->numWant = 50;
    req->port = 6881;
    req->extensions = 0;
    req->user_data = nullptr;
    udpTracker.addRequest(req);
  }

  std::array<unsigned char, 64 * 1024> buf;
  size_t off = 1;
  while (off + 2 <= size) {
    size_t len = (size_t(data[off]) << 8) | data[off + 1];
    off += 2;
    if (len == 0 || len > size - off) {
      break;
    }
    // Send what the UDP tracker client has queued, as DHTInteractionCommand does
    // after each receive round, so there is a request in flight to answer.
    while (!udpTracker.getPendingRequests().empty()) {
      unsigned char out[1024];
      std::string addr;
      uint16_t port;
      if (udpTracker.createRequest(out, sizeof(out), addr, port,
                                   global::wallclock()) == -1) {
        break;
      }
      udpTracker.requestSent(global::wallclock());
    }
    memcpy(buf.data(), data + off, len);
    off += len;
    try {
      if (buf[0] == 'd') {
        receiver.receiveMessage(remoteAddr, remotePort, buf.data(), len);
      }
      else {
        if (onPathTracker && len >= 8 &&
            !udpTracker.getInflightRequests().empty()) {
          uint32_t tid = udpTracker.getInflightRequests().front()->transactionId;
          buf[4] = tid >> 24;
          buf[5] = tid >> 16;
          buf[6] = tid >> 8;
          buf[7] = tid;
        }
        std::shared_ptr<UDPTrackerRequest> req;
        udpTracker.receiveReply(req, buf.data(), len, remoteAddr, remotePort,
                                global::wallclock());
      }
    }
    catch (Exception& e) {
    }
  }
  udpTracker.failAll();
  return 0;
}
