#include "AsyncRequestHandler.h"
#include "utils/Log.h"

namespace http {

AsyncRequestHandler::AsyncRequestHandler(int default_timeout_sec)
    : default_timeout_sec_(default_timeout_sec), cancelled_(false) {

  if (default_timeout_sec_ <= 0) {
    default_timeout_sec_ = 30; // Default 30 second timeout
  }

  LOGI("AsyncRequestHandler created with default timeout: {}s",
       default_timeout_sec_);
}

bool AsyncRequestHandler::ShouldCancel() const { return cancelled_.load(); }

void AsyncRequestHandler::Cancel() {
  cancelled_ = true;
  LOGW("AsyncRequestHandler operation cancelled");
}

} // namespace http