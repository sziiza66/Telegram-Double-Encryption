#pragma once

#include "QtCore/QString"
#include <filesystem>
#include <optional>

#include "config.h"

namespace DoubleEncryption {

std::filesystem::path Get2E2GramDefaultWD();

class SettingsManager {
    using Path = std::filesystem::path;

    struct Settings {
        Path secret_storage_dir_path = "";
        Path gpg_path = "";
        Path gpg_homedir_path = "";
        QString device_model = "";
        QString system_version = "";
        std::string api_hash = "b18441a1ff607e10a989891a5462e627";
        int api_id = 2040;
        bool is_properly_initialized = true;
    };
public:
    static SettingsManager& Instance();

    const Path& GetSecretStorageDirPath() const;
    const Path& GetGPGPath() const;
    const Path& GetGPGHomedirPath() const;
    const QString& GetDeviceModel() const;
    const QString& GetSystemVersion() const;
    // const QString& GetDisguisePassphrase() const;
    const char* GetApiHash() const;
    int GetApiId() const;
    // bool IsClientDisguised() const;

    void SwitchDisguise();

private:
    SettingsManager(const Path& settings_path);

    static Settings LoadSettings(const Path& settings_path);

private:
    Path settings_path_;
    Settings settings_;

private:
    static constexpr char settings_file_name_[] = "e2egramSettings.json";

    static constexpr char secret_storage_dir_path_option_name_[] = "secretStoragePath";
    static constexpr char gpg_path_option_name_[] = "gpgPath";
    static constexpr char gpg_homedir_path_option_name_[] = "gpgHomedirPath";
    // static constexpr char is_client_disguised_option_name_[] = "isClientDisguised";
    // static constexpr char disguise_passphrase_option_name_[] = "disguisePassphrase";

    static constexpr char api_hash_option_name_[] = "apiHash";
    static constexpr char api_id_option_name_[] = "apiId";

    static constexpr char device_model_option_name_[] = "deviceModel";
    static constexpr char system_version_option_name_[] = "systemVersion";

    static constexpr char secret_storage_dir_default_path_[] = "secrets";
};

}  // namespace DoubleEncryption
