#include <cassert>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "utils/DB.h"
#include "utils/Log.h"

namespace {
void RunTest(void (*test_func)(), const std::string &test_name) {
  std::cout << "--- Running test: " << test_name << " ---\n";
  try {
    test_func();
    std::cout << "--- PASS: " << test_name << " ---\n\n";
  } catch (const std::exception &e) {
    std::cout << "--- FAIL: " << test_name << " with exception: " << e.what()
              << " ---\n\n";
  } catch (...) {
    std::cout << "--- FAIL: " << test_name << " with unknown exception ---\n\n";
  }
}

void TestDatabaseOpen() {
  DB db(":memory:");
  CHECK(db.IsOpen());

  DB db2 = std::move(db);
  CHECK(db2.IsOpen());
  CHECK(!db.IsOpen());
}

void TestSimpleExecuteAndTableCreation() {
  DB db(":memory:");
  CHECK(db.IsOpen());

  const std::string create_table_sql = "CREATE TABLE users ("
                                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                       "name TEXT NOT NULL,"
                                       "age INTEGER,"
                                       "height REAL,"
                                       "bio TEXT,"
                                       "photo BLOB"
                                       ");";

  bool success = db.Execute(create_table_sql);
  CHECK(success);
  LOGI("Table 'users' created successfully.");

  bool failure = db.Execute("CREATE GARBAGE;");
  CHECK(!failure);
  LOGI("Correctly failed to execute invalid SQL.");
}

void TestInsertAndSelect() {
  DB db(":memory:");
  db.Execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age "
             "INTEGER, height REAL, photo BLOB);");

  auto insert_stmt_opt = db.Prepare(
      "INSERT INTO users (name, age, height, photo) VALUES (?, ?, ?, ?);");
  CHECK(insert_stmt_opt.has_value());
  auto &insert_stmt = insert_stmt_opt.value();

  std::string name = "John Doe";
  int age = 30;
  double height = 180.5;
  std::vector<uint8_t> photo_data = {0xDE, 0xAD, 0xBE, 0xEF};

  CHECK(insert_stmt.Bind(1, name));
  CHECK(insert_stmt.Bind(2, age));
  CHECK(insert_stmt.Bind(3, height));
  CHECK(insert_stmt.Bind(4, photo_data));

  CHECK(insert_stmt.Execute());
  CHECK(db.GetLastInsertRowId() == 1);
  LOGI("Inserted John Doe, row id: {}", db.GetLastInsertRowId());

  insert_stmt.Reset();
  CHECK(insert_stmt.Bind(1, "Jane Smith"));
  CHECK(insert_stmt.BindNull(2)); // age is NULL
  CHECK(insert_stmt.Bind(3, 165.2));
  CHECK(insert_stmt.BindNull(4)); // photo is NULL
  CHECK(insert_stmt.Execute());
  CHECK(db.GetLastInsertRowId() == 2);
  LOGI("Inserted Jane Smith, row id: {}", db.GetLastInsertRowId());

  auto select_stmt_opt = db.Prepare(
      "SELECT id, name, age, height, photo FROM users WHERE id = ?;");
  CHECK(select_stmt_opt.has_value());
  auto &select_stmt = select_stmt_opt.value();

  CHECK(select_stmt.Bind(1, 1));
  CHECK(select_stmt.Step()); // Move to the first row

  CHECK(std::get<int64_t>(select_stmt.GetColumn(0)) == 1);
  CHECK(std::get<std::string>(select_stmt.GetColumn(1)) == name);
  CHECK(std::get<int64_t>(select_stmt.GetColumn(2)) == age);
  CHECK(std::abs(std::get<double>(select_stmt.GetColumn(3)) - height) < 0.001);
  CHECK(std::get<std::vector<uint8_t>>(select_stmt.GetColumn(4)) == photo_data);

  LOGI("Verified John Doe's data.");
  CHECK(!select_stmt.Step());

  select_stmt.Reset();
  CHECK(select_stmt.Bind(1, 2));
  CHECK(select_stmt.Step());
  CHECK(std::get<int64_t>(select_stmt.GetColumn(0)) == 2);
  CHECK(std::get<std::string>(select_stmt.GetColumn(1)) == "Jane Smith");
  CHECK(std::holds_alternative<std::monostate>(
      select_stmt.GetColumn(2))); // age is NULL
  CHECK(std::abs(std::get<double>(select_stmt.GetColumn(3)) - 165.2) < 0.001);
  CHECK(std::holds_alternative<std::monostate>(
      select_stmt.GetColumn(4))); // photo is NULL
  LOGI("Verified Jane Smith's data (with NULLs).");
}

void TestTransactions() {
  DB db(":memory:");
  db.Execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);");

  CHECK(db.BeginTransaction());
  CHECK(db.Execute("INSERT INTO items (name) VALUES ('committed item');"));
  CHECK(db.Commit());

  auto stmt1_opt =
      db.Prepare("SELECT COUNT(*) FROM items WHERE name = 'committed item';");
  CHECK(stmt1_opt.has_value());
  auto &stmt1 = stmt1_opt.value();
  CHECK(stmt1.Step());
  CHECK(std::get<int64_t>(stmt1.GetColumn(0)) == 1);
  LOGI("Commit successful.");

  CHECK(db.BeginTransaction());
  CHECK(db.Execute("INSERT INTO items (name) VALUES ('rolled-back item');"));
  CHECK(db.Rollback());

  auto stmt2_opt =
      db.Prepare("SELECT COUNT(*) FROM items WHERE name = 'rolled-back item';");
  CHECK(stmt2_opt.has_value());
  auto &stmt2 = stmt2_opt.value();
  CHECK(stmt2.Step());
  CHECK(std::get<int64_t>(stmt2.GetColumn(0)) == 0);
  LOGI("Rollback successful.");
}

void TestErrorHandling() {
  DB db(":memory:");

  auto stmt_opt = db.Prepare("SELECT * FROM non_existent_table;");
  CHECK(!stmt_opt.has_value());
  LOGE("Correctly handled failed prepare for non-existent table.");

  db.Execute("CREATE TABLE test (id INT);");
  auto insert_stmt_opt = db.Prepare("INSERT INTO test (id) VALUES (?);");
  CHECK(insert_stmt_opt.has_value());

  auto val = insert_stmt_opt->GetColumn(0);
  CHECK(std::holds_alternative<std::monostate>(val));
  LOGE("Correctly handled GetColumn before Step.");
}
} // namespace

int main() {
  std::cout << std::fixed << std::setprecision(2);

  RunTest(TestDatabaseOpen, "TestDatabaseOpen");
  RunTest(TestSimpleExecuteAndTableCreation,
          "TestSimpleExecuteAndTableCreation");
  RunTest(TestInsertAndSelect, "TestInsertAndSelect");
  RunTest(TestTransactions, "TestTransactions");
  RunTest(TestErrorHandling, "TestErrorHandling");

  std::cout << "All tests completed.";

  return 0;
}
