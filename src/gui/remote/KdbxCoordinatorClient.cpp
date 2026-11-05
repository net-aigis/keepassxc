/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "KdbxCoordinatorClient.h"

#include "CoordinatorByteLimits.h"
#include "CoordinatorConfigValidation.h"

#include <QCryptographicHash>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslSocket>
#include <QTimer>

KdbxCoordinatorClient::KdbxCoordinatorClient(const QUrl& service,
                                               const QString& databaseId,
                                               const QByteArray& accessToken,
                                               const QString& owner,
                                               QObject* parent)
    : QObject(parent)
    , m_service(service)
    , m_databaseId(databaseId)
    , m_accessToken(accessToken)
    , m_owner(owner)
{
    m_renewTimer.setInterval(25000); // below server's 90-second expiry
    connect(&m_renewTimer, &QTimer::timeout, this, [this] {
        QString error;
        if (!renew(&error)) {
            invalidate(); // Fail closed in the database widget immediately.
        }
    });
}

KdbxCoordinatorClient::~KdbxCoordinatorClient()
{
    QString ignored;
    release(&ignored); // best effort; server lease expiry is the ultimate fallback
    m_accessToken.fill(char(0));
    m_lease.fill(char(0));
    m_revision.fill(char(0));
}

void KdbxCoordinatorClient::invalidate()
{
    if (m_lost) {
        return;
    }
    m_lost = true;
    m_renewTimer.stop();
    if (!m_lease.isEmpty()) {
        emit leaseLost();
    }
}

QByteArray KdbxCoordinatorClient::hash(const QByteArray& bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
}

QByteArray KdbxCoordinatorClient::field(const QByteArray& body, const QString& key)
{
    return CoordinatorConfigValidation::jsonStringField(body, key);
}

namespace {
void applyCoordinatorTls(QNetworkRequest& req)
{
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
    req.setSslConfiguration(ssl);
}

QByteArray readBoundedBody(QNetworkReply* reply, qint64 maxBytes, QString* transportError)
{
    const auto declared = reply->header(QNetworkRequest::ContentLengthHeader).toLongLong();
    if (declared > maxBytes) {
        if (transportError) {
            *transportError = QStringLiteral("Coordinator response exceeds permitted size");
        }
        return {};
    }

    QByteArray body;
    if (declared > 0) {
        body.reserve(static_cast<int>(qMin(declared, maxBytes)));
    }
    while (!reply->atEnd()) {
        const QByteArray chunk = reply->read(64 * 1024);
        if (chunk.isEmpty()) {
            break;
        }
        if (static_cast<qint64>(body.size()) + chunk.size() > maxBytes) {
            if (transportError) {
                *transportError = QStringLiteral("Coordinator response exceeds permitted size");
            }
            return {};
        }
        body.append(chunk);
    }
    return body;
}
} // namespace

KdbxCoordinatorClient::Response KdbxCoordinatorClient::request(const QByteArray& method,
                                                                 const QString& action,
                                                                 const QByteArray& payload,
                                                                 const QByteArray& lease,
                                                                 const QByteArray& expectedRevision)
{
    Response result;
    // Same printable-ASCII / URL rules as the settings UI — fail closed here too.
    if (!CoordinatorConfigValidation::validate(
             m_service.toString(), m_databaseId, QString::fromUtf8(m_accessToken))
             .isEmpty()) {
        result.transportError = QStringLiteral("Invalid coordinator configuration");
        return result;
    }
    if (static_cast<qint64>(payload.size()) > CoordinatorByteLimits::MaxKdbxBytes) {
        result.transportError = QStringLiteral("KDBX exceeds permitted in-memory size");
        return result;
    }

    QUrl url = m_service;
    url.setPath(m_service.path().replace(QRegularExpression(QStringLiteral("/$")), {}) +
                QStringLiteral("/v1/databases/") + m_databaseId + action);
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    applyCoordinatorTls(req);
    req.setRawHeader("Authorization", "Bearer " + m_accessToken);
    req.setRawHeader("Cache-Control", "no-store");
    req.setRawHeader("Accept", "application/json, application/octet-stream");
    if (!lease.isEmpty()) {
        req.setRawHeader("X-KDBX-Lease", lease);
    }
    if (!expectedRevision.isEmpty()) {
        req.setRawHeader("If-Match", '"' + expectedRevision + '"');
    }
    QNetworkReply* reply = nullptr;
    if (method == "GET") {
        reply = m_network.get(req);
    } else if (method == "POST") {
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        reply = m_network.post(req, payload);
    } else if (method == "PUT") {
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
        reply = m_network.put(req, payload);
    } else if (method == "DELETE") {
        reply = m_network.deleteResource(req);
    } else {
        result.transportError = QStringLiteral("Unsupported HTTP method");
        return result;
    }

    // Synchronous only inside a worker: no freezing the GUI.
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    // Never ignore certificate errors; abort so TLS failures stay transport errors.
    QObject::connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->abort();
    });
    timeout.start(40000);
    if (!reply->isFinished()) {
        loop.exec();
    }
    timeout.stop();
    result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    result.etag = reply->rawHeader("ETag");
    const qint64 maxBytes = (method == "GET" && action == QStringLiteral("/file"))
        ? CoordinatorByteLimits::MaxKdbxBytes
        : CoordinatorByteLimits::MaxControlBytes;
    result.bytes = readBoundedBody(reply, maxBytes, &result.transportError);
    if (reply->error() != QNetworkReply::NoError && result.status == 0 &&
        result.transportError.isEmpty()) {
        result.transportError = reply->errorString();
    }
    reply->deleteLater();
    return result;
}

bool KdbxCoordinatorClient::acquire(QString* error)
{
    if (!m_lease.isEmpty()) {
        if (error) *error = QStringLiteral("Already holding a lease");
        return false;
    }
    const QJsonObject body{{QStringLiteral("owner"), m_owner}};
    auto result = request("POST", QStringLiteral("/lock"), QJsonDocument(body).toJson(QJsonDocument::Compact));
    m_busy = CoordinatorConfigValidation::isBusyLockStatus(result.status);
    if (result.status != 200) {
        if (error) *error = m_busy ? QStringLiteral("Database is locked by another editor")
                                  : QStringLiteral("Acquire failed: HTTP %1 %2").arg(result.status).arg(result.transportError);
        return false;
    }
    CoordinatorConfigValidation::LeaseFields leaseFields;
    if (!CoordinatorConfigValidation::parseLeaseResponse(result.bytes, &leaseFields)) {
        if (error) *error = QStringLiteral("Malformed coordinator lease response");
        return false;
    }
    m_lease = leaseFields.token;
    m_revision = leaseFields.revision;
    m_lost = false;
    m_renewTimer.start();
    return true;
}

bool KdbxCoordinatorClient::download(QByteArray* encryptedDatabase, bool* exists, QString* error)
{
    if (!hasLease()) {
        if (error) *error = QStringLiteral("Editing lease missing or lost");
        return false;
    }
    auto result = request("GET", QStringLiteral("/file"));
    if (result.status == 404 && m_revision == "0") {
        if (exists) *exists = false;
        if (encryptedDatabase) encryptedDatabase->clear();
        return true;
    }
    if (result.status != 200) {
        if (error) *error = QStringLiteral("Download failed: HTTP %1 %2").arg(result.status).arg(result.transportError);
        return false;
    }
    if (!CoordinatorConfigValidation::matchesDownloadedContent(result.bytes, result.etag, m_revision)) {
        invalidate();
        if (error) *error = QStringLiteral("Remote database changed unexpectedly");
        return false;
    }
    if (encryptedDatabase) *encryptedDatabase = result.bytes;
    if (exists) *exists = true;
    return hasLease();
}

bool KdbxCoordinatorClient::publish(const QByteArray& encryptedDatabase, QString* error)
{
    if (!hasLease()) {
        if (error) *error = QStringLiteral("No valid editing lease");
        return false;
    }
    if (!CoordinatorConfigValidation::isAcceptableKdbxPayload(encryptedDatabase.size())) {
        if (error) *error = QStringLiteral("KDBX empty or exceeds permitted in-memory size");
        return false;
    }
    const auto result = request("PUT", QStringLiteral("/file"), encryptedDatabase, m_lease, m_revision);
    if (CoordinatorConfigValidation::isLostLeaseStatus(result.status)
        || CoordinatorConfigValidation::isStaleRevisionStatus(result.status)) {
        invalidate();
    }
    if (result.status != 200) {
        if (error) *error = QStringLiteral("Publication failed: HTTP %1 %2").arg(result.status).arg(result.transportError);
        return false;
    }
    const auto expected = hash(encryptedDatabase);
    if (!CoordinatorConfigValidation::matchesPublishAck(result.bytes, result.etag, expected)) {
        invalidate();
        if (error) *error = QStringLiteral("Publication acknowledgement mismatch");
        return false;
    }
    if (!hasLease()) {
        if (error) *error = QStringLiteral("Editing lease lost while publishing");
        return false;
    }
    m_revision = expected;
    return true;
}

bool KdbxCoordinatorClient::renew(QString* error)
{
    if (!hasLease()) {
        if (error) *error = QStringLiteral("Editing lease lost");
        return false;
    }
    const auto result = request("POST", QStringLiteral("/renew"), QByteArrayLiteral("{}"), m_lease);
    if (!CoordinatorConfigValidation::isSuccessfulRenewStatus(result.status)) {
        invalidate();
        if (error) *error = QStringLiteral("Lease renewal failed: HTTP %1 %2").arg(result.status).arg(result.transportError);
        return false;
    }
    return true;
}

bool KdbxCoordinatorClient::release(QString* error)
{
    m_renewTimer.stop();
    if (m_lease.isEmpty()) return true;
    const auto token = m_lease;
    m_lease.clear();
    m_revision.clear();
    m_lost = true;
    const auto result = request("DELETE", QStringLiteral("/lock"), {}, token);
    if (result.status != 204 && result.status != 409) {
        if (error) *error = QStringLiteral("Lease release not confirmed: HTTP %1 %2").arg(result.status).arg(result.transportError);
        return false;
    }
    return true;
}
