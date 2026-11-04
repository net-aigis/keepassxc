/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <QString>

/**
 * Shared HTTPS coordinator endpoint checks for KeePassXC settings UI and client.
 * Loopback HTTP is allowed only for localhost / 127.0.0.1.
 */
namespace CoordinatorConfigValidation {
QString validate(const QString& url, const QString& databaseId, const QString& accessToken);
}
