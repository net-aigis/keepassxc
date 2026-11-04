/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "CoordinatorConfigValidation.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUrl>

namespace CoordinatorConfigValidation {

namespace {
const QRegularExpression& hex64()
{
    static const QRegularExpression re(QStringLiteral("^[a-f0-9]{64}$"));
    return re;
}
} // namespace

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

QByteArray jsonStringField(const QByteArray& body, const QString& key)
{
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return {};
    }
    return document.object().value(key).toString().toUtf8();
}

bool isValidLeaseToken(const QByteArray& token)
{
    return hex64().match(QString::fromLatin1(token)).hasMatch();
}

bool isValidRevision(const QByteArray& revision)
{
    return revision == "0" || hex64().match(QString::fromLatin1(revision)).hasMatch();
}

bool parseLeaseResponse(const QByteArray& body, LeaseFields* out)
{
    if (!out) {
        return false;
    }
    const QByteArray token = jsonStringField(body, QStringLiteral("token"));
    const QByteArray revision = jsonStringField(body, QStringLiteral("revision"));
    if (!isValidLeaseToken(token) || !isValidRevision(revision)) {
        return false;
    }
    out->token = token;
    out->revision = revision;
    return true;
}

bool matchesPublishAck(const QByteArray& body,
                       const QByteArray& etag,
                       const QByteArray& expectedRevisionHex)
{
    if (!isValidLeaseToken(expectedRevisionHex)) {
        return false;
    }
    const QByteArray revision = jsonStringField(body, QStringLiteral("revision"));
    return revision == expectedRevisionHex && etag == '"' + expectedRevisionHex + '"';
}

bool matchesDownloadedContent(const QByteArray& ciphertext,
                              const QByteArray& etag,
                              const QByteArray& expectedRevisionHex)
{
    if (!isValidLeaseToken(expectedRevisionHex) || ciphertext.isEmpty()) {
        return false;
    }
    const QByteArray digest =
        QCryptographicHash::hash(ciphertext, QCryptographicHash::Sha256).toHex();
    return digest == expectedRevisionHex && etag == '"' + expectedRevisionHex + '"';
}

} // namespace CoordinatorConfigValidation
