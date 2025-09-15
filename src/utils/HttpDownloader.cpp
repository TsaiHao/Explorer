//
// Created by Hao, Zaijun on 2025/9/12.
//

#include <vector>
#include <format>

#include "HttpDownloader.h"
#include "curl/curl.h"
#include "utils/Status.h"

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::vector<uint8_t>* data) {
  size_t total_size = size * nmemb;
  data->insert(data->end(), static_cast<uint8_t*>(contents), static_cast<uint8_t*>(contents) + total_size);
  return total_size;
}

class HttpDownloader::Impl {
public:
  Impl(std::string_view url, std::string_view path, int timeoutMs)
      : m_url(url), m_path(path), m_timeout_ms(timeoutMs) {}

  Status DownloadSync() {
    std::string full_url = m_url + m_path;
    
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
      return SdkFailure("Failed to initialize curl");
    }
    
    m_data.clear();
    m_http_status_code = 0;
    
    curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(m_timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "HttpDownloader/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    m_http_status_code = static_cast<int>(http_code);
    
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
      std::string msg = std::format("Failed to download from {}: {}", full_url, curl_easy_strerror(res));
      return SdkFailure(msg);
    }
    
    if (http_code >= 400) {
      std::string msg = std::format("Failed to download from {}: {}", full_url, http_code);
      return SdkFailure(msg);
    }
    
    return Ok();
  }

  int GetHttpStatusCode() const { return m_http_status_code; }

  std::vector<uint8_t> GetData() const {
    return m_data;
  }

private:
  std::string m_url;
  std::string m_path;
  int m_timeout_ms = 10000;

  int m_http_status_code = 0;
  std::vector<uint8_t> m_data;
};

HttpDownloader::HttpDownloader(std::string_view url, std::string_view path,
                               int timeoutMs)
    : m_impl(new HttpDownloader::Impl(url, path, timeoutMs)) {}

HttpDownloader::~HttpDownloader() = default;

Status HttpDownloader::DownloadSync() { return m_impl->DownloadSync(); }

int HttpDownloader::GetHttpStatusCode() const {
  return m_impl->GetHttpStatusCode();
}

std::vector<uint8_t> HttpDownloader::GetData() const {
  return m_impl->GetData();
}
