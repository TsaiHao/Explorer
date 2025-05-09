//
// Created by Hao, Zaijun on 2025/4/28.
//

#include "Log.h"
#include "System.h"

#include <fcntl.h>
#include <unistd.h>

namespace utils {
std::string ReadFileToBuffer(const std::string &file_path) {
  CHECK(!file_path.empty());

  const int fd = open(file_path.data(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    perror("Opening file failed");
    if (errno == ENOENT) {
      LOG(ERROR) << "File " << file_path << " does not exist";
    } else if (errno == EACCES) {
      LOG(ERROR) << "File " << file_path << " access denied";
    } else {
      LOG(ERROR) << "Opening " << file_path << " failed, error = " << strerror(errno);
    }
    exit(1);
  }

  auto file_size = lseek(fd, 0, SEEK_END);
  CHECK(file_size > 0);

  CHECK(lseek(fd, 0, SEEK_SET) != -1);

  std::string file_content(file_size, 0);
  auto read_bytes = read(fd, file_content.data(), file_size);
  CHECK(read_bytes == file_size);
  close(fd);

  return file_content;
}
}