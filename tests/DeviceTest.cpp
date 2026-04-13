#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mocks/MockFridaApi.h"
#include "mocks/MockSystemApi.h"

#include "frida/Device.h"

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;

class DeviceTest : public ::testing::Test {
protected:
  void SetUp() override {
    mock_frida_ = std::make_shared<frida::MockFridaApi>();
    mock_system_ = std::make_shared<utils::MockSystemApi>();
  }

  // Helper: set up mock expectations for Device constructor
  void ExpectDeviceConstruction() {
    static FridaDeviceManager fake_manager;
    static FridaDeviceList fake_device_list;

    EXPECT_CALL(*mock_frida_, ManagerNew())
        .WillOnce(Return(&fake_manager));
    EXPECT_CALL(*mock_frida_, ManagerEnumerateDevicesSync(_, _, _))
        .WillOnce(Return(&fake_device_list));
    // Stub returns 1 device; ObjectRef is called on it
    EXPECT_CALL(*mock_frida_, ObjectRef(_))
        .WillRepeatedly([](gpointer p) { return p; });
  }

  // Helper: set up mock expectations for Device destructor
  void ExpectDeviceDestruction() {
    EXPECT_CALL(*mock_frida_, ManagerCloseSync(_, _, _)).Times(1);
    EXPECT_CALL(*mock_frida_, Unref(_)).Times(testing::AnyNumber());
  }

  std::unique_ptr<frida::Device> CreateDevice() {
    ExpectDeviceConstruction();
    ExpectDeviceDestruction();
    return std::make_unique<frida::Device>(mock_frida_, mock_system_);
  }

  std::shared_ptr<frida::MockFridaApi> mock_frida_;
  std::shared_ptr<utils::MockSystemApi> mock_system_;
};

TEST_F(DeviceTest, CreateSessionRejectsNonObject) {
  auto device = CreateDevice();

  auto result = device->CreateSession(nlohmann::json::array());
  ASSERT_TRUE(result.IsErr());
  EXPECT_EQ(result.UnwrapErr().Code(), StatusCode::kBadArgument);
}

TEST_F(DeviceTest, CreateSessionRejectsEmptyConfig) {
  auto device = CreateDevice();

  // Config with app but process not found
  nlohmann::json config = {{"app", "com.test.app"}};

  EXPECT_CALL(*mock_system_, FindProcessByName(std::string_view("com.test.app")))
      .WillRepeatedly(Return(std::nullopt));

  auto result = device->CreateSession(config);
  ASSERT_TRUE(result.IsErr());
  EXPECT_EQ(result.UnwrapErr().Code(), StatusCode::kNotFound);
}

TEST_F(DeviceTest, CreateSessionDuplicatePid) {
  auto device = CreateDevice();

  // First, create a session successfully
  static FridaSession fake_session;
  utils::ProcessInfo proc{"com.test.app", "com.test.app", 1234};

  EXPECT_CALL(*mock_system_, FindProcessByName(std::string_view("com.test.app")))
      .WillOnce(Return(std::nullopt))  // duplicate check in CreateSession
      .WillOnce(Return(proc));         // AttachToAppFromConfig lookup

  EXPECT_CALL(*mock_frida_, DeviceAttachSync(_, 1234, _, _, _))
      .WillOnce(Return(&fake_session));
  EXPECT_CALL(*mock_frida_, SignalConnect(_, _, _, _))
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*mock_frida_, SessionDetachSync(_, _, _))
      .Times(testing::AnyNumber());

  nlohmann::json config = {{"app", "com.test.app"}};
  auto result = device->CreateSession(config);
  ASSERT_TRUE(result.IsOk());

  // Second attempt with same app — should detect duplicate
  EXPECT_CALL(*mock_system_, FindProcessByName(std::string_view("com.test.app")))
      .WillOnce(Return(proc));  // duplicate check finds existing

  auto result2 = device->CreateSession(config);
  ASSERT_TRUE(result2.IsErr());
  EXPECT_EQ(result2.UnwrapErr().Code(), StatusCode::kInvalidOperation);
}

TEST_F(DeviceTest, ExtractAppNameFromConfig) {
  auto device = CreateDevice();

  nlohmann::json config = {{"app", "com.example.app"}};

  EXPECT_CALL(*mock_system_, FindProcessByName(std::string_view("com.example.app")))
      .WillRepeatedly(Return(std::nullopt));

  auto result = device->CreateSession(config);
  // Should fail with NotFound (process not found), not BadArgument (no app name)
  ASSERT_TRUE(result.IsErr());
  EXPECT_NE(result.UnwrapErr().Code(), StatusCode::kBadArgument);
}

TEST_F(DeviceTest, GetSessionStatisticsEmpty) {
  auto device = CreateDevice();

  auto stats = device->GetSessionStatistics();
  EXPECT_EQ(stats["active_sessions"], 0);
  EXPECT_EQ(stats["total_sessions_created"], 0);
  EXPECT_EQ(stats["pending_spawns"], 0);
}

TEST_F(DeviceTest, DrainMessagesSessionNotFound) {
  auto device = CreateDevice();

  auto result = device->DrainSessionMessages(9999);
  ASSERT_TRUE(result.IsErr());
  EXPECT_EQ(result.UnwrapErr().Code(), StatusCode::kNotFound);
}

TEST_F(DeviceTest, RemoveSessionNotFound) {
  auto device = CreateDevice();

  auto status = device->RemoveSession(9999);
  EXPECT_EQ(status.Code(), StatusCode::kNotFound);
}

TEST_F(DeviceTest, GetSessionInfoNotFound) {
  auto device = CreateDevice();

  auto result = device->GetSessionInfo(9999);
  ASSERT_TRUE(result.IsErr());
  EXPECT_EQ(result.UnwrapErr().Code(), StatusCode::kNotFound);
}

TEST_F(DeviceTest, ListSessionsEmpty) {
  auto device = CreateDevice();

  auto result = device->ListAllSessions();
  ASSERT_TRUE(result.IsOk());

  auto data = result.Unwrap();
  EXPECT_EQ(data["total_count"], 0);
  EXPECT_TRUE(data["sessions"].empty());
}
