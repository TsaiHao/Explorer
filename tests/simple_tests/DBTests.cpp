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
  assert(db.IsOpen());

  DB db2 = std::move(db);
  assert(db2.IsOpen());
  assert(!db.IsOpen());
}

void TestSimpleExecuteAndTableCreation() {
  DB db(":memory:");
  assert(db.IsOpen());

  const std::string create_table_sql = "CREATE TABLE users ("
                                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                       "name TEXT NOT NULL,"
                                       "age INTEGER,"
                                       "height REAL,"
                                       "bio TEXT,"
                                       "photo BLOB"
                                       ");";

  bool success = db.Execute(create_table_sql);
  assert(success);
  LOG(INFO) << "Table 'users' created successfully.";

  bool failure = db.Execute("CREATE GARBAGE;");
  assert(!failure);
  LOG(INFO) << "Correctly failed to execute invalid SQL.";
}

void TestInsertAndSelect() {
  DB db(":memory:");
  db.Execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age "
             "INTEGER, height REAL, photo BLOB);");

  auto insert_stmt_opt = db.Prepare(
      "INSERT INTO users (name, age, height, photo) VALUES (?, ?, ?, ?);");
  assert(insert_stmt_opt.has_value());
  auto &insert_stmt = insert_stmt_opt.value();

  std::string name = "John Doe";
  int age = 30;
  double height = 180.5;
  std::vector<uint8_t> photo_data = {0xDE, 0xAD, 0xBE, 0xEF};

  assert(insert_stmt.Bind(1, name));
  assert(insert_stmt.Bind(2, age));
  assert(insert_stmt.Bind(3, height));
  assert(insert_stmt.Bind(4, photo_data));

  assert(insert_stmt.Execute());
  assert(db.GetLastInsertRowId() == 1);
  LOG(INFO) << "Inserted John Doe, row id: " << db.GetLastInsertRowId();

  insert_stmt.Reset();
  assert(insert_stmt.Bind(1, "Jane Smith"));
  assert(insert_stmt.BindNull(2)); // age is NULL
  assert(insert_stmt.Bind(3, 165.2));
  assert(insert_stmt.BindNull(4)); // photo is NULL
  assert(insert_stmt.Execute());
  assert(db.GetLastInsertRowId() == 2);
  LOG(INFO) << "Inserted Jane Smith, row id: " << db.GetLastInsertRowId();

  auto select_stmt_opt = db.Prepare(
      "SELECT id, name, age, height, photo FROM users WHERE id = ?;");
  assert(select_stmt_opt.has_value());
  auto &select_stmt = select_stmt_opt.value();

  assert(select_stmt.Bind(1, 1));
  assert(select_stmt.Step()); // Move to the first row

  assert(std::get<int64_t>(select_stmt.GetColumn(0)) == 1);
  assert(std::get<std::string>(select_stmt.GetColumn(1)) == name);
  assert(std::get<int64_t>(select_stmt.GetColumn(2)) == age);
  assert(std::abs(std::get<double>(select_stmt.GetColumn(3)) - height) < 0.001);
  assert(std::get<std::vector<uint8_t>>(select_stmt.GetColumn(4)) ==
         photo_data);

  LOG(INFO) << "Verified John Doe's data.";
  assert(!select_stmt.Step());

  select_stmt.Reset();
  assert(select_stmt.Bind(1, 2));
  assert(select_stmt.Step());
  assert(std::get<int64_t>(select_stmt.GetColumn(0)) == 2);
  assert(std::get<std::string>(select_stmt.GetColumn(1)) == "Jane Smith");
  assert(std::holds_alternative<std::monostate>(
      select_stmt.GetColumn(2))); // age is NULL
  assert(std::abs(std::get<double>(select_stmt.GetColumn(3)) - 165.2) < 0.001);
  assert(std::holds_alternative<std::monostate>(
      select_stmt.GetColumn(4))); // photo is NULL
  LOG(INFO) << "Verified Jane Smith's data (with NULLs).";
}

void TestTransactions() {
  DB db(":memory:");
  db.Execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);");

  assert(db.BeginTransaction());
  assert(db.Execute("INSERT INTO items (name) VALUES ('committed item');"));
  assert(db.Commit());

  auto stmt1_opt =
      db.Prepare("SELECT COUNT(*) FROM items WHERE name = 'committed item';");
  assert(stmt1_opt.has_value());
  auto &stmt1 = stmt1_opt.value();
  assert(stmt1.Step());
  assert(std::get<int64_t>(stmt1.GetColumn(0)) == 1);
  LOG(INFO) << "Commit successful.";

  assert(db.BeginTransaction());
  assert(db.Execute("INSERT INTO items (name) VALUES ('rolled-back item');"));
  assert(db.Rollback());

  auto stmt2_opt =
      db.Prepare("SELECT COUNT(*) FROM items WHERE name = 'rolled-back item';");
  assert(stmt2_opt.has_value());
  auto &stmt2 = stmt2_opt.value();
  assert(stmt2.Step());
  assert(std::get<int64_t>(stmt2.GetColumn(0)) == 0);
  LOG(INFO) << "Rollback successful.";
}

void TestErrorHandling() {
  DB db(":memory:");

  auto stmt_opt = db.Prepare("SELECT * FROM non_existent_table;");
  assert(!stmt_opt.has_value());
  LOG(INFO) << "Correctly handled failed prepare for non-existent table.";

  db.Execute("CREATE TABLE test (id INT);");
  auto insert_stmt_opt = db.Prepare("INSERT INTO test (id) VALUES (?);");
  assert(insert_stmt_opt.has_value());

  auto val = insert_stmt_opt->GetColumn(0);
  assert(std::holds_alternative<std::monostate>(val));
  LOG(INFO) << "Correctly handled GetColumn before Step.";
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
