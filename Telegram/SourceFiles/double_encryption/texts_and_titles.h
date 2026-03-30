#pragma once

#include "QtCore/QString"

namespace DoubleEncryption {

constexpr char peer_context_menu_establish_connection_button_name[] = "Establish secure connection";
constexpr char peer_context_menu_close_connection_button_name[] = "Close secure connection";
constexpr char settings_manage_public_keys_button_name[] = "Manage public keys";
constexpr char settings_manage_private_keys_button_name[] = "Manage private keys";
constexpr char interpret_message_as_encryption_request_button_name[] = "Accept encryption request";
constexpr char secure_connection_public_keys_menu_title_[] = "Select public key to establish secure connection";
constexpr char secure_connection_wait_box_text_[] = "Waiting for user to accept your request. Close this box to cancel this attempt.";


QString MakeSecureConnectionInfo(const QString& sig_fingerprint,
                                 const QString& enc_fingerprint);

}  // namespace DoubleEncryption
