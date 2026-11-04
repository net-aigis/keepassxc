/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <QtGlobal>

/**
 * Keep aligned with NetAigis KeySafe CoordinatorByteLimits.
 * KDBX payloads and control JSON must not grow without bound in memory.
 */
namespace CoordinatorByteLimits {
constexpr qint64 MaxKdbxBytes = 64LL * 1024 * 1024;
constexpr qint64 MaxControlBytes = 16LL * 1024;
} // namespace CoordinatorByteLimits
