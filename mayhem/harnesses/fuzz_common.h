// Shared setup for the aria2 fuzz harnesses (mayhem/harnesses/*.cc).
//
// Process-wide state set once here, read-only afterwards:
//  * aria2::Platform (OpenSSL / socket library init, the same object aria2c's main() creates);
//  * the console is suppressed and logging is limited to errors so each input does not spend its
//    time formatting debug lines. Nothing an input does can change these settings (the harnesses
//    never pass input-controlled options to LogFactory).
// Every parser object a harness drives is created per input.
#ifndef ARIA2_FUZZ_COMMON_H
#define ARIA2_FUZZ_COMMON_H

#include "common.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include "Platform.h"
#include "LogFactory.h"
#include "Logger.h"
#include "console.h"

namespace aria2fuzz {

inline void quietInit()
{
  static aria2::Platform* platform = nullptr;
  if (platform) {
    return;
  }
  platform = new aria2::Platform();
  aria2::global::initConsole(true);
  aria2::LogFactory::setLogFile("");
  aria2::LogFactory::setConsoleOutput(false);
  aria2::LogFactory::setLogLevel(aria2::Logger::A2_ERROR);
  aria2::LogFactory::setConsoleLogLevel(aria2::Logger::A2_ERROR);
  aria2::LogFactory::reconfigure();
}

// A unique scratch path under $TMPDIR (default /tmp), created with mkstemps so
// concurrent fuzzer processes never share a file. Returns "" on failure.
inline std::string writeTemp(const uint8_t* data, size_t size,
                             const std::string& suffix)
{
  const char* dir = getenv("TMPDIR");
  std::string tmpl = std::string(dir && *dir ? dir : "/tmp") +
                     "/aria2fuzz-XXXXXX" + suffix;
  int fd = mkstemps(&tmpl[0], static_cast<int>(suffix.size()));
  if (fd < 0) {
    return "";
  }
  size_t off = 0;
  while (off < size) {
    ssize_t n = write(fd, data + off, size - off);
    if (n <= 0) {
      close(fd);
      unlink(tmpl.c_str());
      return "";
    }
    off += static_cast<size_t>(n);
  }
  close(fd);
  return tmpl;
}

} // namespace aria2fuzz

#endif // ARIA2_FUZZ_COMMON_H
