#include "nlohmann/json.hpp"
#include "utils/HttpDownloader.h"
#include "utils/Log.h"

namespace {
void TestSchemaFetch() {
  constexpr std::string_view kUrl = "http://explorer.zaijun.org";
  constexpr std::string_view kPath = "/config-schema.json";

  auto downloader = HttpDownloader(kUrl, kPath);
  auto status = downloader.DownloadSync();
  CHECK_STATUS(status);

  auto http_status = downloader.GetHttpStatusCode();
  CHECK(http_status == 200);

  auto data = downloader.GetData();
  auto json = nlohmann::json::parse(data);
  LOGI("Fetched JSON: {}", json.dump(2));
}
} // namespace

int main() {
  TestSchemaFetch();
  return 0;
}