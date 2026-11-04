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
} // namespace CoordinatorConfigValidation
