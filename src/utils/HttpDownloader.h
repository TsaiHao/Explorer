#pragma once
#include <cstdint>
#include <memory>

#include "utils/Macros.h"
#include "utils/Status.h"

class HttpDownloader {
public:
  HttpDownloader(std::string_view url, std::string_view path,
                 int timeoutMs = 10000);
  ~HttpDownloader();

  Status DownloadSync();

  int GetHttpStatusCode() const;
  std::vector<uint8_t> GetData() const;

private:
  DISABLE_COPY_AND_MOVE(HttpDownloader);

  class Impl;
  std::unique_ptr<Impl> m_impl;
};