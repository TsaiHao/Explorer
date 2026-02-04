//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <signal.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "Application.h"
#include "ApplicationDaemon.h"
#include "utils/Log.h"
#include "utils/System.h"
#include "version.h"

namespace {

// Configuration structure for main application
struct MainConfig {
  bool daemon_mode = true;                    // Default to daemon mode
  bool foreground = false;                    // Run in foreground (don't fork)
  std::string host = "0.0.0.0";               // Bind host
  int port = 34512;                           // Default daemon port
  std::string config_dir = "/data/local/tmp"; // Configuration directory
  std::string pid_file_path =
      "/data/local/tmp/explorer.pid"; // PID file location
  std::string config_file = "";       // Config file path (triggers legacy mode)
  bool legacy_mode = false;           // Use legacy Application class
  bool show_help = false;             // Show help message
  bool show_version = false;          // Show version
};

// Global pointers for signal handlers
static Application *g_legacy_app = nullptr;
static ApplicationDaemon *g_daemon_app = nullptr;
static MainConfig g_config;

// Signal handler for graceful shutdown
void signal_handler(int signal_num) {
  const char *signal_name = "UNKNOWN";
  switch (signal_num) {
  case SIGINT:
    signal_name = "SIGINT";
    break;
  case SIGTERM:
    signal_name = "SIGTERM";
    break;
  case SIGHUP:
    signal_name = "SIGHUP";
    break;
  }

  if (g_config.daemon_mode) {
    syslog(LOG_INFO, "Received %s, initiating graceful shutdown...",
           signal_name);
  } else {
    LOGI("Received {} ({}), initiating graceful shutdown...", signal_name,
         signal_num);
  }

  // Shutdown the appropriate application type
  if (g_daemon_app) {
    g_daemon_app->Shutdown();
  } else if (g_legacy_app) {
    g_legacy_app->Shutdown();
  }

  // Special handling for SIGHUP in daemon mode (could be used for config
  // reload)
  if (signal_num == SIGHUP && g_config.daemon_mode) {
    if (g_config.daemon_mode) {
      syslog(LOG_INFO, "SIGHUP received - config reload not yet implemented");
    } else {
      LOGW("SIGHUP received - config reload not yet implemented");
    }
  }
}

void setup_signal_handlers() {
  // Set up signal handlers for graceful shutdown
  struct sigaction sa;
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; // Restart interrupted system calls

  if (sigaction(SIGINT, &sa, nullptr) == -1) {
    LOGE("Failed to register SIGINT handler: {}", strerror(errno));
    exit(1);
  }

  if (sigaction(SIGTERM, &sa, nullptr) == -1) {
    LOGE("Failed to register SIGTERM handler: {}", strerror(errno));
    exit(1);
  }

  if (sigaction(SIGHUP, &sa, nullptr) == -1) {
    LOGE("Failed to register SIGHUP handler: {}", strerror(errno));
    exit(1);
  }

  // Ignore SIGPIPE to prevent crashes on broken connections
  signal(SIGPIPE, SIG_IGN);

  LOGI("Signal handlers configured successfully");
}

void show_help(const char *program_name) {
  std::cout << "Explorer - FRIDA Dynamic Instrumentation Tool\n";
  std::cout << "Usage: " << program_name << " [options]\n\n";
  std::cout << "Mode Options:\n";
  std::cout << "  --daemon              Run in daemon mode (default)\n";
  std::cout << "  --legacy              Run in legacy config-file mode\n";
  std::cout << "  --config FILE         Run with config file (legacy mode)\n";
  std::cout
      << "  --foreground          Run daemon in foreground (don't fork)\n\n";
  std::cout << "Daemon Configuration:\n";
  std::cout
      << "  --host HOST           Bind to specific host (default: 0.0.0.0)\n";
  std::cout
      << "  --port PORT           Listen on specific port (default: 34512)\n";
  std::cout << "  --config-dir DIR      Configuration directory (default: "
               "/data/local/tmp)\n";
  std::cout << "  --pid-file PATH       PID file location (default: "
               "/data/local/tmp/explorer.pid)\n\n";
  std::cout << "General Options:\n";
  std::cout << "  --help                Show this help message\n";
  std::cout << "  --version             Show version information\n\n";
  std::cout << "Examples:\n";
  std::cout << "  " << program_name
            << "                              # Run daemon on default port\n";
  std::cout << "  " << program_name
            << " --port 8080                 # Run daemon on port 8080\n";
  std::cout << "  " << program_name
            << " --foreground                # Run daemon in foreground\n";
  std::cout
      << "  " << program_name
      << " --config /path/config.json  # Run legacy mode with config file\n";
  std::cout
      << "  " << program_name
      << " --legacy                    # Run legacy mode (default config)\n";
  std::cout << "  " << program_name
            << " --legacy           # Run in legacy config-file mode\n\n";
}

void show_version() {
  std::cout << "Explorer version " << VERSION_STRING << "\n";
  std::cout << "FRIDA Dynamic Instrumentation Framework\n";
  std::cout << "Built for Android TV platforms (armv7a)\n";
}

bool parse_arguments(int argc, char *argv[], MainConfig &config) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "--help") {
      config.show_help = true;
      return true;
    } else if (arg == "--version") {
      config.show_version = true;
      return true;
    } else if (arg == "--daemon") {
      config.daemon_mode = true;
      config.legacy_mode = false;
    } else if (arg == "--legacy") {
      config.legacy_mode = true;
      config.daemon_mode = false;
    } else if (arg == "--config" && i + 1 < argc) {
      config.config_file = argv[++i];
      config.legacy_mode = true;
      config.daemon_mode = false;
    } else if (arg == "--foreground") {
      config.foreground = true;
    } else if (arg == "--host" && i + 1 < argc) {
      config.host = argv[++i];
    } else if (arg == "--port" && i + 1 < argc) {
      try {
        config.port = std::stoi(argv[++i]);
        if (config.port <= 0 || config.port > 65535) {
          std::cerr << "Error: Port must be between 1 and 65535\n";
          return false;
        }
      } catch (const std::exception &e) {
        std::cerr << "Error: Invalid port number: " << argv[i] << "\n";
        return false;
      }
    } else if (arg == "--config-dir" && i + 1 < argc) {
      config.config_dir = argv[++i];
      // Update PID file path based on config directory
      config.pid_file_path = config.config_dir + "/explorer.pid";
    } else if (arg == "--pid-file" && i + 1 < argc) {
      config.pid_file_path = argv[++i];
    } else {
      std::cerr << "Error: Unknown argument: " << arg << "\n";
      std::cerr << "Use --help for usage information.\n";
      return false;
    }
  }

  return true;
}

bool create_pid_file(const std::string &pid_file_path) {
  // Check if PID file already exists
  std::ifstream existing_file(pid_file_path);
  if (existing_file.good()) {
    pid_t existing_pid;
    existing_file >> existing_pid;
    existing_file.close();

    // Check if process is still running
    if (kill(existing_pid, 0) == 0) {
      std::cerr << "Error: Another explorer daemon is already running (PID: "
                << existing_pid << ")\n";
      return false;
    } else {
      // Stale PID file, remove it
      LOGW("Removing stale PID file: {}", pid_file_path);
      unlink(pid_file_path.c_str());
    }
  }

  // Create new PID file
  std::ofstream pid_file(pid_file_path);
  if (!pid_file.good()) {
    std::cerr << "Error: Cannot create PID file: " << pid_file_path << " ("
              << strerror(errno) << ")\n";
    return false;
  }

  pid_file << getpid() << std::endl;
  pid_file.close();

  if (!pid_file.good()) {
    std::cerr << "Error: Failed to write to PID file: " << pid_file_path
              << "\n";
    return false;
  }

  LOGI("Created PID file: {} (PID: {})", pid_file_path, getpid());
  return true;
}

void remove_pid_file(const std::string &pid_file_path) {
  if (unlink(pid_file_path.c_str()) == 0) {
    LOGI("Removed PID file: {}", pid_file_path);
  } else {
    LOGW("Failed to remove PID file {}: {}", pid_file_path, strerror(errno));
  }
}

bool daemonize() {
  LOGI("Daemonizing process...");

  // Fork the first time
  pid_t pid = fork();
  if (pid < 0) {
    std::cerr << "Error: Failed to fork daemon process: " << strerror(errno)
              << "\n";
    return false;
  }

  if (pid > 0) {
    // Parent process exits
    std::cout << "Explorer daemon started with PID: " << pid << "\n";
    exit(0);
  }

  // Child process continues
  // Create new session and become session leader
  if (setsid() < 0) {
    syslog(LOG_ERR, "Failed to create new session: %s", strerror(errno));
    return false;
  }

  // Fork a second time to ensure we're not a session leader
  // (prevents daemon from acquiring a controlling terminal)
  pid = fork();
  if (pid < 0) {
    syslog(LOG_ERR, "Failed to fork second time: %s", strerror(errno));
    return false;
  }

  if (pid > 0) {
    // First child exits
    exit(0);
  }

  // Second child continues as daemon
  // Change working directory to root
  if (chdir("/") < 0) {
    syslog(LOG_ERR, "Failed to change working directory to /: %s",
           strerror(errno));
    return false;
  }

  // Set file permissions mask
  umask(0);

  // Close all open file descriptors
  for (int fd = sysconf(_SC_OPEN_MAX) - 1; fd >= 0; --fd) {
    close(fd);
  }

  // Redirect stdin, stdout, stderr to /dev/null
  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd >= 0) {
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    if (null_fd > STDERR_FILENO) {
      close(null_fd);
    }
  }

  // Open syslog for daemon logging
  openlog("explorer-daemon", LOG_PID | LOG_CONS, LOG_DAEMON);
  syslog(LOG_INFO, "Daemon process created successfully (PID: %d)", getpid());

  return true;
}

int run_legacy_mode(const std::vector<std::string_view> &args) {
  LOGI("Starting Explorer in legacy config-file mode");

  try {
    Application app(args);
    g_legacy_app = &app;

    LOGI("Starting legacy application (Press Ctrl+C for graceful shutdown)");
    app.Run();

    g_legacy_app = nullptr;
    LOGI("Legacy application exited gracefully");
    return 0;

  } catch (const std::exception &e) {
    LOGE("Exception in legacy mode: {}", e.what());
    g_legacy_app = nullptr;
    return 1;
  }
}

int run_daemon_mode(const std::vector<std::string_view> &args) {
  if (g_config.daemon_mode) {
    syslog(LOG_INFO, "Starting Explorer daemon on %s:%d", g_config.host.c_str(),
           g_config.port);
  } else {
    LOGI("Starting Explorer daemon on {}:{}", g_config.host, g_config.port);
  }

  try {
    ApplicationDaemon daemon(args);
    g_daemon_app = &daemon;

    // Initialize daemon
    auto init_status = daemon.Initialize();
    if (!init_status.Ok()) {
      LOGE("Failed to initialize daemon: {}", init_status.Message());
      g_daemon_app = nullptr;
      return 1;
    }

    LOGI("Daemon initialized successfully, starting HTTP server...");

    // Run daemon (this blocks until shutdown)
    auto run_status = daemon.Run();
    if (!run_status.Ok()) {
      LOGE("Daemon run failed: {}", run_status.Message());
      g_daemon_app = nullptr;
      return 1;
    }

    g_daemon_app = nullptr;
    LOGI("Daemon exited gracefully");

    return 0;

  } catch (const std::exception &e) {
    if (g_config.daemon_mode) {
      syslog(LOG_ERR, "Exception in daemon mode: %s", e.what());
    } else {
      LOGE("Exception in daemon mode: {}", e.what());
    }
    g_daemon_app = nullptr;
    return 1;
  }
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  std::cout << "Explorer - FRIDA Dynamic Instrumentation Tool\n";
  // Parse command line arguments
  if (!parse_arguments(argc, argv, g_config)) {
    return 1;
  }

  // Handle help and version requests
  if (g_config.show_help) {
    show_help(argv[0]);
    return 0;
  }

  if (g_config.show_version) {
    show_version();
    return 0;
  }

  // Convert argv to string_view vector for application constructors
  std::vector<std::string_view> args;
  for (int i = 0; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  // Set up signal handlers early
  setup_signal_handlers();

  // Handle legacy mode
  if (g_config.legacy_mode) {
    return run_legacy_mode(args);
  }

  // Daemon mode - handle daemonization if not in foreground
  if (g_config.daemon_mode && !g_config.foreground) {
    if (!daemonize()) {
      std::cerr << "Error: Failed to daemonize process\n";
      return 1;
    }
    // After daemonization, we're now running as a daemon process
    // Standard output is redirected to /dev/null, use syslog for logging
  } else if (g_config.daemon_mode && g_config.foreground) {
    std::cout << "Running Explorer daemon in foreground mode\n";
    std::cout << "Server will be available at http://" << g_config.host << ":"
              << g_config.port << "\n";
    std::cout << "Press Ctrl+C to stop the daemon\n";
  }

  // Create PID file for daemon mode
  if (g_config.daemon_mode) {
    if (!create_pid_file(g_config.pid_file_path)) {
      return 1;
    }
  }

  // Run the daemon
  int exit_code = run_daemon_mode(args);

  // Clean up PID file
  if (g_config.daemon_mode) {
    remove_pid_file(g_config.pid_file_path);
  }

  // Close syslog if we opened it
  if (g_config.daemon_mode && !g_config.foreground) {
    closelog();
  }

  return exit_code;
}