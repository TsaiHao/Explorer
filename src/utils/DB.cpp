//
// Created by Hao, Zaijun on 2025/6/24.
//

#include "DB.h"
#include "utils/Log.h"

Statement::Statement(sqlite3_stmt *stmt, sqlite3 *db) : mStmt(stmt), mDb(db) {}

Statement::~Statement() {
  if (mStmt != nullptr) {
    sqlite3_finalize(mStmt);
  }
}

Statement::Statement(Statement &&other) noexcept
    : mStmt(other.mStmt), mDb(other.mDb), mHasStepped(other.mHasStepped) {
  other.mStmt = nullptr;
  other.mDb = nullptr;
}

Statement &Statement::operator=(Statement &&other) noexcept {
  if (this != &other) {
    if (mStmt != nullptr) {
      sqlite3_finalize(mStmt);
    }
    mStmt = other.mStmt;
    mDb = other.mDb;
    mHasStepped = other.mHasStepped;
    other.mStmt = nullptr;
    other.mDb = nullptr;
  }
  return *this;
}

bool Statement::Bind(int index, int value) {
  return Bind(index, static_cast<int64_t>(value));
}

bool Statement::Bind(int index, int64_t value) {
  if (sqlite3_bind_int64(mStmt, index, value) != SQLITE_OK) {
    LOG(INFO) << "Failed to bind int64: " << sqlite3_errmsg(mDb);
    return false;
  }
  return true;
}

bool Statement::Bind(int index, double value) {
  if (sqlite3_bind_double(mStmt, index, value) != SQLITE_OK) {
    LOG(INFO) << "Failed to bind double: " << sqlite3_errmsg(mDb);
    return false;
  }
  return true;
}

bool Statement::Bind(int index, std::string_view text) {
  if (sqlite3_bind_text(mStmt, index, text.data(),
                        static_cast<int>(text.length()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    LOG(INFO) << "Failed to bind text: " << sqlite3_errmsg(mDb);
    return false;
  }
  return true;
}

bool Statement::Bind(int index, const std::vector<uint8_t> &blob) {
  if (sqlite3_bind_blob(mStmt, index, blob.data(),
                        static_cast<int>(blob.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    LOG(INFO) << "Failed to bind blob: " << sqlite3_errmsg(mDb);
    return false;
  }
  return true;
}

bool Statement::BindNull(int index) {
  if (sqlite3_bind_null(mStmt, index) != SQLITE_OK) {
    LOG(INFO) << "Failed to bind null: " << sqlite3_errmsg(mDb);
    return false;
  }
  return true;
}

bool Statement::Step() {
  int rc = sqlite3_step(mStmt);
  if (!mHasStepped) {
    mHasStepped = true;
  }

  if (rc == SQLITE_ROW) {
    return true; // A row of data is ready.
  }
  if (rc == SQLITE_DONE) {
    return false; // The statement has finished executing.
  }

  LOG(INFO) << "Step error: " << sqlite3_errmsg(mDb);
  return false; // An error occurred.
}

bool Statement::Execute() {
  int rc = sqlite3_step(mStmt);
  if (!mHasStepped) {
    mHasStepped = true;
  }

  if (rc != SQLITE_DONE) {
    LOG(INFO) << "Execute error: " << sqlite3_errmsg(mDb);
    Reset();
    return false;
  }
  return true;
}

void Statement::Reset() {
  sqlite3_reset(mStmt);
  sqlite3_clear_bindings(mStmt);
  mHasStepped = false;
}

int Statement::GetColumnCount() { return sqlite3_column_count(mStmt); }

std::string Statement::GetColumnName(int index) {
  const char *name = sqlite3_column_name(mStmt, index);
  return (name != nullptr) ? name : "";
}

int Statement::GetColumnType(int index) {
  return sqlite3_column_type(mStmt, index);
}

Statement::Value Statement::GetColumn(int index) {
  if (!mHasStepped) {
    LOG(INFO) << "Cannot get column data before calling Step() at least once.";
    return {}; // Return monostate
  }
  if (index < 0 || index >= GetColumnCount()) {
    LOG(INFO) << "Column index " << index << " is out of bounds.";
    return {};
  }

  int type = GetColumnType(index);
  switch (type) {
  case SQLITE_INTEGER:
    return sqlite3_column_int64(mStmt, index);
  case SQLITE_FLOAT:
    return sqlite3_column_double(mStmt, index);
  case SQLITE_TEXT: {
    const auto *text = sqlite3_column_text(mStmt, index);
    int size = sqlite3_column_bytes(mStmt, index);
    return std::string(reinterpret_cast<const char *>(text), size);
  }
  case SQLITE_BLOB: {
    const void *blob_data = sqlite3_column_blob(mStmt, index);
    int size = sqlite3_column_bytes(mStmt, index);
    const auto *start = static_cast<const uint8_t *>(blob_data);
    return std::vector<uint8_t>(start, start + size);
  }
  case SQLITE_NULL:
  default:
    return {}; // Return monostate
  }
}

DB::DB(const std::string &path, OpenMode mode) {
  int flags = static_cast<int>(mode);
  if (sqlite3_open_v2(path.c_str(), &mDb, flags, nullptr) != SQLITE_OK) {
    if (mDb != nullptr) {
      LOG(INFO) << "Can't open database: " << sqlite3_errmsg(mDb);
      sqlite3_close(mDb);
    } else {
      LOG(INFO)
          << "Can't open database: sqlite3_open_v2 failed to allocate memory";
    }
    mDb = nullptr;
  }
}

DB::~DB() {
  if (mDb != nullptr) {
    sqlite3_close_v2(mDb);
  }
}

DB::DB(DB &&other) noexcept : mDb(other.mDb) { other.mDb = nullptr; }

DB &DB::operator=(DB &&other) noexcept {
  if (this != &other) {
    if (mDb != nullptr) {
      sqlite3_close_v2(mDb);
    }
    mDb = other.mDb;
    other.mDb = nullptr;
  }
  return *this;
}

bool DB::IsOpen() const { return mDb != nullptr; }

std::string DB::GetLastErrorMsg() const {
  return (mDb != nullptr) ? sqlite3_errmsg(mDb) : "Database is not open.";
}

int DB::GetLastErrorCode() const {
  return (mDb != nullptr) ? sqlite3_errcode(mDb) : -1;
}

bool DB::Execute(const std::string &sql) {
  char *err_msg = nullptr;
  if (sqlite3_exec(mDb, sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
    LOG(INFO) << "SQL error: " << err_msg;
    sqlite3_free(err_msg);
    return false;
  }
  return true;
}

std::optional<Statement> DB::Prepare(const std::string &sql) {
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(mDb, sql.c_str(), static_cast<int>(sql.length()),
                         &stmt, nullptr) != SQLITE_OK) {
    LOG(INFO) << "Failed to prepare statement: " << GetLastErrorMsg();
    sqlite3_finalize(stmt); // It's safe to call finalize on a NULL pointer.
    return std::nullopt;
  }
  return Statement(stmt, mDb);
}

bool DB::BeginTransaction() { return Execute("BEGIN TRANSACTION;"); }

bool DB::Commit() { return Execute("COMMIT;"); }

bool DB::Rollback() { return Execute("ROLLBACK;"); }

int64_t DB::GetLastInsertRowId() { return sqlite3_last_insert_rowid(mDb); }
