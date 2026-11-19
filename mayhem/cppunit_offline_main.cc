// mayhem/test.sh's runner for aria2's cppunit suite: test/AllTest.cc's main(), except that it
// leaves out the two fixtures that need a multicast-capable network interface
// (LpdMessageDispatcherTest, LpdMessageReceiverTest: "Failed to set a socket option, cause: No
// such device" when offline). The commit image's suite, and rlenv's graded rebuilds, run with no
// network, where those two fail on every tree. Everything else (973 tests) runs as upstream's
// runner runs it, linked from the same test objects.
#include "common.h"

#include <cstring>
#include <iostream>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/TestSuite.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>

#include "Platform.h"
#include "SocketCore.h"
#include "util.h"
#include "console.h"
#include "LogFactory.h"
#include "prefs.h"

int main(int argc, char* argv[])
{
  aria2::global::initConsole(false);
  aria2::Platform platform;

  aria2::SocketCore::setProtocolFamily(AF_INET);
  aria2::setDefaultAIFlags(0);
  aria2::util::mkdirs(A2_TEST_OUT_DIR);

  aria2::LogFactory::setConsoleLogLevel(aria2::V_DEBUG);
  aria2::LogFactory::reconfigure();

  static const char* const needsNetwork[] = {
      "aria2::LpdMessageDispatcherTest",
      "aria2::LpdMessageReceiverTest",
  };
  // The registry's suite is kept alive (never deleted) because the filtered suite takes
  // ownership of the fixtures it runs.
  CppUnit::Test* all = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
  auto suite = new CppUnit::TestSuite("offline");
  for (int i = 0; i < all->getChildTestCount(); ++i) {
    CppUnit::Test* t = all->getChildTestAt(i);
    bool skip = false;
    for (const char* name : needsNetwork) {
      skip = skip || t->getName() == name;
    }
    if (skip) {
      std::cerr << "skipped (needs a network interface): " << t->getName()
                << std::endl;
    }
    else {
      suite->addTest(t);
    }
  }
  CppUnit::TextUi::TestRunner runner;
  runner.addTest(suite);
  runner.setOutputter(
      new CppUnit::CompilerOutputter(&runner.result(), std::cerr));
  return runner.run() ? 0 : 1;
}
