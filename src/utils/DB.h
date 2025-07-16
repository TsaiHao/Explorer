#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "sqlite3.h"

class DB;
class Statement;

class Statement {
public:
  using Value = std::variant<std::monostate, int64_t, double, std::string,
                             std::vector<uint8_t>>;

  ~Statement();

  Statement(Statement &&other) noexcept;
  Statement &operator=(Statement &&other) noexcept;
  Statement(const Statement &) = delete;
  Statement &operator=(const Statement &) = delete;

  bool Bind(int index, int value);
  bool Bind(int index, int64_t value);
  bool Bind(int index, double value);
  bool Bind(int index, std::string_view text);
  bool Bind(int index, const std::vector<uint8_t> &blob);
  bool BindNull(int index);

  bool Step();
  bool Execute();
  void Reset();

  int GetColumnCount();
  std::string GetColumnName(int index);
  int GetColumnType(int index);
  Value GetColumn(int index);

private:
  friend class DB;
  Statement(sqlite3_stmt *stmt, sqlite3 *db);

  sqlite3_stmt *m_stmt = nullptr;
  sqlite3 *m_db = nullptr;
  bool m_has_stepped = false;
};

class DB {
public:
  enum class OpenMode : uint8_t {
    ReadOnly = SQLITE_OPEN_READONLY,
    ReadWrite = SQLITE_OPEN_READWRITE,
    ReadWriteCreate = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
  };

  explicit DB(const std::string &path,
              OpenMode mode = OpenMode::ReadWriteCreate);
  ~DB();

  DB(DB &&other) noexcept;
  DB &operator=(DB &&other) noexcept;
  DB(const DB &) = delete;
  DB &operator=(const DB &) = delete;

  bool IsOpen() const;
  std::string GetLastErrorMsg() const;
  int GetLastErrorCode() const;

  bool Execute(const std::string &sql);
  std::optional<Statement> Prepare(const std::string &sql);

  bool BeginTransaction();
  bool Commit();
  bool Rollback();

  int64_t GetLastInsertRowId();

private:
  sqlite3 *m_db = nullptr;
};
