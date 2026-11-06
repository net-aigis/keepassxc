/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <QByteArray>
#include <QString>

/**
 * Shared HTTPS coordinator endpoint checks for KeePassXC settings UI and client.
 * Loopback HTTP is allowed only for localhost / 127.0.0.1.
 */
namespace CoordinatorConfigValidation {
QString validate(const QString& url, const QString& databaseId, const QString& accessToken);

/** Extract a JSON string field; empty on parse error or missing key. */
QByteArray jsonStringField(const QByteArray& body, const QString& key);

/** HTTP 423 means another editor holds the exclusive lease. */
bool isBusyLockStatus(int httpStatus);

/** HTTP 200: lock acquired or ciphertext download succeeded. */
bool isSuccessfulAcquireStatus(int httpStatus);
bool isSuccessfulDownloadStatus(int httpStatus);

/** HTTP 404 with revision "0" means the shared database has no tip yet. */
bool isEmptyDatabaseDownload(int httpStatus, const QByteArray& revision);

/** HTTP 409: lease lost / conflict; 412: stale If-Match revision. */
bool isLostLeaseStatus(int httpStatus);
bool isStaleRevisionStatus(int httpStatus);

/** Non-empty KDBX body within CoordinatorByteLimits::MaxKdbxBytes. */
bool isAcceptableKdbxPayload(qint64 sizeBytes);

/** HTTP 200 means lease renew or publish succeeded; anything else fails closed. */
bool isSuccessfulRenewStatus(int httpStatus);
bool isSuccessfulPublishStatus(int httpStatus);

/** DELETE /lock: 204 released, 409 already gone — both acceptable. */
bool isAcceptableReleaseStatus(int httpStatus);

/** Lease token: exactly 64 lowercase hex digits. */
bool isValidLeaseToken(const QByteArray& token);

/** Revision: "0" (empty database) or 64 lowercase hex digits. */
bool isValidRevision(const QByteArray& revision);

struct LeaseFields {
    QByteArray token;
    QByteArray revision;
};

/**
 * Parse a coordinator lock JSON body. Returns false when the document is
 * malformed or token/revision fail the hex rules above.
 */
bool parseLeaseResponse(const QByteArray& body, LeaseFields* out);

/**
 * Publish acknowledgement must echo the SHA-256 of the uploaded ciphertext
 * both in the JSON revision field and as a quoted ETag.
 */
bool matchesPublishAck(const QByteArray& body,
                       const QByteArray& etag,
                       const QByteArray& expectedRevisionHex);

/**
 * Downloaded ciphertext must hash to the lease revision and carry a matching
 * quoted ETag. Mismatch means the remote changed; caller must fail closed.
 */
bool matchesDownloadedContent(const QByteArray& ciphertext,
                              const QByteArray& etag,
                              const QByteArray& expectedRevisionHex);
} // namespace CoordinatorConfigValidation
