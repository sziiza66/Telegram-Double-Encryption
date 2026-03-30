#include "texts_and_titles.h"

namespace DoubleEncryption {

QString MakeSecureConnectionInfo(const QString& sig_key_desc,
                                const QString& enc_key_desc) {
    return "Request was signed with: \n" + sig_key_desc + "\n\n" +
           "And encrypted with:\n" + enc_key_desc + '\n' +
           "Make sure you trust those keys.";    
}

}  // namespace DoubleEncryption
