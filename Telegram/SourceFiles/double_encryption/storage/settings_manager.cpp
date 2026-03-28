#include "settings_manager.h"

#include <QtCore/qdir.h>
#include <QtCore/qlogging.h>
#include <exception>
#include <fstream>
#include "nlohmann/json.hpp"

#include "base/platform/base_platform_info.h"
#include "settings.h"
#include "core/application.h"

namespace DoubleEncryption {

std::filesystem::path Get2E2GramDefaultWD() {
    QString wd = QDir(cExeDir()).absolutePath() + "/e2egramdata/";
    QDir().mkdir(wd);
    return QDir(wd).filesystemAbsolutePath();
}

SettingsManager& SettingsManager::Instance() {
    static SettingsManager manager(Get2E2GramDefaultWD() / settings_file_name_);
    return manager;
}

SettingsManager::SettingsManager(const Path& settings_path)
    : settings_path_(settings_path), settings_(LoadSettings(settings_path)) {
}

const SettingsManager::Path& SettingsManager::GetSecretStorageDirPath() const {
    return settings_.secret_storage_dir_path;
}

const SettingsManager::Path& SettingsManager::GetGPGPath() const {
    return settings_.gpg_path;
}

const SettingsManager::Path& SettingsManager::GetGPGHomedirPath() const {
    return settings_.gpg_homedir_path;
}

const QString& SettingsManager::GetDeviceModel() const {
    return settings_.device_model;
}

const QString& SettingsManager::GetSystemVersion() const {
    return settings_.system_version;
}

const char* SettingsManager::GetApiHash() const {
    return settings_.api_hash.data();
}

int SettingsManager::GetApiId() const {
    return settings_.api_id;
}

SettingsManager::Settings SettingsManager::LoadSettings(const Path& settings_path) {
    using json = nlohmann::json;

    Settings settings;

    try {
        json settings_parsed = json::parse(std::ifstream(settings_path));
        auto GetStrFromJson = [&](const std::string& key) -> std::string {
            if (!settings_parsed.contains(key) || settings_parsed[key].is_null()) {
                return "";
            }
            std::string value = settings_parsed[key].get<std::string>();
            return value;
        };

        auto cur = std::filesystem::current_path();

        settings.secret_storage_dir_path = GetStrFromJson(secret_storage_dir_path_option_name_);
        settings.gpg_path = GetStrFromJson(gpg_path_option_name_);
        settings.gpg_homedir_path = GetStrFromJson(gpg_homedir_path_option_name_);
        // settings.is_client_disguised = settings_parsed.value(is_client_disguised_option_name_, false);
        settings.device_model = QString::fromStdString(GetStrFromJson(device_model_option_name_));
        settings.system_version = QString::fromStdString(GetStrFromJson(system_version_option_name_));
        // settings.disguise_passphrase = QString::fromStdString(GetStrFromJson(disguise_passphrase_option_name_));
        settings.api_hash = GetStrFromJson(api_hash_option_name_);
        settings.api_id = settings_parsed.value(api_id_option_name_, 2040);

        auto IsPathValid = [](const Path& path, const std::string& path_name, bool await_dir, bool await_exists,
                              bool await_exec) -> bool {
            if (path.empty()) {
                return false;
            }

            std::error_code ec;

            bool exists = std::filesystem::exists(path, ec);

            if (await_exists && (!exists || ec)) {
                qCritical() << "option" << path_name << "=" << path.c_str() << "does not exist or is not accessible.";
                qCritical() << path_name << "is set to default.";
                return false;
            }

            if (exists && await_dir && (!std::filesystem::is_directory(path, ec) || ec)) {
                qCritical() << "option" << path_name << "=" << path.c_str() << "is not a directory.";
                qCritical() << path_name << "is set to default.";
                return false;
            }

            if (exists) {
                auto perms = std::filesystem::status(path, ec).permissions();
                if (ec) {
                    qCritical() << "option" << path_name << "=" << path.c_str() << "permission check failed.";
                    qCritical() << path_name << "is set to default.";
                    return false;
                }

                auto p = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
                if (await_exec) {
                    p |= std::filesystem::perms::owner_exec;
                }
                if ((perms & p) != p) {
                    qCritical() << "option" << path_name << "=" << path.c_str()
                                << "is not readable or/and not writable.";
                    qCritical() << path_name << "is set to default.";
                    return false;
                }
            }

            return true;
        };

        if (!IsPathValid(settings.secret_storage_dir_path, secret_storage_dir_path_option_name_, true, false, false)) {
            settings.secret_storage_dir_path = secret_storage_dir_default_path_;
        }
        if (!IsPathValid(settings.gpg_path, gpg_path_option_name_, false, true, true)) {
            settings.gpg_path = "";
        }
        if (!IsPathValid(settings.gpg_homedir_path, gpg_homedir_path_option_name_, true, false, false)) {
            settings.gpg_homedir_path = "";
        }

        if (settings.device_model.isEmpty()) {
            settings.device_model = Platform::DeviceModelPretty();
        }

        if (settings.system_version.isEmpty()) {
            settings.system_version = Platform::SystemVersionPretty();
        }

    } catch (const std::exception& e) {
        qCritical() << "Error while trying to load e2egram settings:";
        qCritical() << e.what();
        // settings.is_client_disguised = true;
        settings.secret_storage_dir_path = secret_storage_dir_default_path_;
        settings.is_properly_initialized = false;
        settings.api_hash = "b18441a1ff607e10a989891a5462e627";
        settings.api_id = 2040;
    }

    auto MakeAbsolute = [](Path& path) -> void {
        if (path.is_relative()) {
            path = Get2E2GramDefaultWD() / path;
        }
    };

    MakeAbsolute(settings.secret_storage_dir_path);
    std::filesystem::create_directory(settings.secret_storage_dir_path);
    if (!settings.gpg_path.empty()) {
        MakeAbsolute(settings.gpg_path);
    }
    if (!settings.gpg_homedir_path.empty()) {
        MakeAbsolute(settings.gpg_homedir_path);
        std::filesystem::create_directory(settings.gpg_homedir_path);
    }

    return settings;
}

}  // namespace DoubleEncryption
