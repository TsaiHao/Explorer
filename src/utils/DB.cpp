//
// Created by Hao, Zaijun on 2025/6/24.
//

#include "DB.h"
#include "utils/Log.h"

Statement::Statement(sqlite3_stmt *stmt, sqlite3 *db)
    : m_stmt(stmt), m_db(db) {}

Statement::~Statement() {
  if (m_stmt != nullptr) {
    sqlite3_finalize(m_stmt);
  }
}

Statement::Statement(Statement &&other) noexcept
    : m_stmt(other.m_stmt), m_db(other.m_db),
      m_has_stepped(other.m_has_stepped) {
  other.m_stmt = nullptr;
  other.m_db = nullptr;
}

Statement &Statement::operator=(Statement &&other) noexcept {
  if (this != &other) {
    if (m_stmt != nullptr) {
      sqlite3_finalize(m_stmt);
    }
    m_stmt = other.m_stmt;
    m_db = other.m_db;
    m_has_stepped = other.m_has_stepped;
    other.m_stmt = nullptr;
    other.m_db = nullptr;
  }
  return *this;
}

bool Statement::Bind(int index, int value) {
  return Bind(index, static_cast<int64_t>(value));
}

bool Statement::Bind(int index, int64_t value) {
  if (sqlite3_bind_int64(m_stmt, index, value) != SQLITE_OK) {
    LOGI("Failed to bind int64: {}", sqlite3_errmsg(m_db));
    return false;
  }
  return true;
}

bool Statement::Bind(int index, double value) {
  if (sqlite3_bind_double(m_stmt, index, value) != SQLITE_OK) {
    LOGI("Failed to bind double: {}", sqlite3_errmsg(m_db));
    return false;
  }
  return true;
}

bool Statement::Bind(int index, std::string_view text) {
  if (sqlite3_bind_text(m_stmt, index, text.data(),
                        static_cast<int>(text.length()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    LOGI("Failed to bind text: {}", sqlite3_errmsg(m_db));
    return false;
  }
  return true;
}

bool Statement::Bind(int index, const std::vector<uint8_t> &blob) {
  if (sqlite3_bind_blob(m_stmt, index, blob.data(),
                        static_cast<int>(blob.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK) {
    LOGI("Failed to bind blob: {}", sqlite3_errmsg(m_db));
    return false;
  }
  return true;
}

bool Statement::BindNull(int index) {
  if (sqlite3_bind_null(m_stmt, index) != SQLITE_OK) {
    LOGI("Failed to bind null: {}", sqlite3_errmsg(m_db));
    return false;
  }
  return true;
}

bool Statement::Step() {
  int rc = sqlite3_step(m_stmt);
  if (!m_has_stepped) {
    m_has_stepped = true;
  }

  if (rc == SQLITE_ROW) {
    return true; // A row of data is ready.
  }
  if (rc == SQLITE_DONE) {
    return false; // The statement has finished executing.
  }

  LOGE("Step error: {}", sqlite3_errmsg(m_db));
  return false; // An error occurred.
}

bool Statement::Execute() {
  int rc = sqlite3_step(m_stmt);
  if (!m_has_stepped) {
    m_has_stepped = true;
  }

  if (rc != SQLITE_DONE) {
    LOGE("Execute error: {}", sqlite3_errmsg(m_db));
    Reset();
    return false;
  }
  return true;
}

void Statement::Reset() {
  sqlite3_reset(m_stmt);
  sqlite3_clear_bindings(m_stmt);
  m_has_stepped = false;
}

int Statement::GetColumnCount() { return sqlite3_column_count(m_stmt); }

std::string Statement::GetColumnName(int index) {
  const char *name = sqlite3_column_name(m_stmt, index);
  return (name != nullptr) ? name : "";
}

int Statement::GetColumnType(int index) {
  return sqlite3_column_type(m_stmt, index);
}

Statement::Value Statement::GetColumn(int index) {
  if (!m_has_stepped) {
    LOGI("Cannot get column data before calling Step() at least once.");
    return {}; // Return monostate
  }
  if (index < 0 || index >= GetColumnCount()) {
    LOGI("Column index {} is out of bounds.", index);
    return {};
  }

  int type = GetColumnType(index);
  switch (type) {
  case SQLITE_INTEGER:
    return sqlite3_column_int64(m_stmt, index);
  case SQLITE_FLOAT:
    return sqlite3_column_double(m_stmt, index);
  case SQLITE_TEXT: {
    const auto *text = sqlite3_column_text(m_stmt, index);
    int size = sqlite3_column_bytes(m_stmt, index);
    return std::string(reinterpret_cast<const char *>(text), size);
  }
  case SQLITE_BLOB: {
    const void *blob_data = sqlite3_column_blob(m_stmt, index);
    int size = sqlite3_column_bytes(m_stmt, index);
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
  if (sqlite3_open_v2(path.c_str(), &m_db, flags, nullptr) != SQLITE_OK) {
    if (m_db != nullptr) {
      LOGE("Can't open database: {}", sqlite3_errmsg(m_db));
      sqlite3_close(m_db);
    } else {
      LOGE("Can't open database: sqlite3_open_v2 failed to allocate memory");
    }
    m_db = nullptr;
  }
}

DB::~DB() {
  if (m_db != nullptr) {
    sqlite3_close_v2(m_db);
  }
}

DB::DB(DB &&other) noexcept : m_db(other.m_db) { other.m_db = nullptr; }

DB &DB::operator=(DB &&other) noexcept {
  if (this != &other) {
    if (m_db != nullptr) {
      sqlite3_close_v2(m_db);
    }
    m_db = other.m_db;
    other.m_db = nullptr;
  }
  return *this;
}

bool DB::IsOpen() const { return m_db != nullptr; }

std::string DB::GetLastErrorMsg() const {
  return (m_db != nullptr) ? sqlite3_errmsg(m_db) : "Database is not open.";
}

int DB::GetLastErrorCode() const {
  return (m_db != nullptr) ? sqlite3_errcode(m_db) : -1;
}

bool DB::Execute(const std::string &sql) {
  char *err_msg = nullptr;
  if (sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &err_msg) !=
      SQLITE_OK) {
    LOGE("SQL error: {}", err_msg);
    sqlite3_free(err_msg);
    return false;
  }
  return true;
}

std::optional<Statement> DB::Prepare(const std::string &sql) {
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(m_db, sql.c_str(), static_cast<int>(sql.length()),
                         &stmt, nullptr) != SQLITE_OK) {
    LOGE("Failed to prepare statement: {}", GetLastErrorMsg());
    sqlite3_finalize(stmt); // It's safe to call finalize on a NULL pointer.
    return std::nullopt;
  }
  return Statement(stmt, m_db);
}

bool DB::BeginTransaction() { return Execute("BEGIN TRANSACTION;"); }

bool DB::Commit() { return Execute("COMMIT;"); }

bool DB::Rollback() { return Execute("ROLLBACK;"); }

int64_t DB::GetLastInsertRowId() { return sqlite3_last_insert_rowid(m_db); }
