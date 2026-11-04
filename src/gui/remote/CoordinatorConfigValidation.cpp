/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "CoordinatorConfigValidation.h"

#include <QRegularExpression>
#include <QUrl>

namespace CoordinatorConfigValidation {

QString validate(const QString& url, const QString& databaseId, const QString& accessToken)
{
    const QUrl service(url);
    const QString host = service.host();
    const bool httpsOk = service.scheme() == QStringLiteral("https");
    const bool loopbackHttpOk = service.scheme() == QStringLiteral("http")
        && (host == QStringLiteral("localhost") || host == QStringLiteral("127.0.0.1"));
    if (!httpsOk && !loopbackHttpOk) {
        return QStringLiteral("Coordinator URL must use HTTPS (HTTP only allowed for localhost).");
    }
    if (!service.userInfo().isEmpty() || service.hasQuery() || service.hasFragment()) {
        return QStringLiteral("Coordinator URL must not include userinfo, query or fragment.");
    }
    if (!QRegularExpression(QStringLiteral("^[a-z0-9_-]{1,96}$")).match(databaseId).hasMatch()) {
        return QStringLiteral("Coordinator database ID must be 1-96 characters: a-z, 0-9, _ or -.");
    }
    const QByteArray tokenBytes = accessToken.toUtf8();
    bool printableAscii = tokenBytes.size() >= 32 && tokenBytes.size() <= 1024;
    for (unsigned char c : tokenBytes) {
        if (c < 0x21 || c > 0x7e) {
            printableAscii = false;
            break;
        }
    }
    if (!printableAscii) {
        return QStringLiteral(
            "Coordinator access token must be 32-1024 printable ASCII characters without whitespace.");
    }
    return {};
}

} // namespace CoordinatorConfigValidation
