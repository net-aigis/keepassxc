/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "gui/remote/CoordinatorConfigValidation.h"

#include <QTest>

class TestCoordinatorConfigValidation : public QObject
{
    Q_OBJECT
private slots:
    void acceptsHttpsAndToken();
    void rejectsCleartextNonLoopback();
    void rejectsShortToken();
    void rejectsBadDatabaseId();
};

void TestCoordinatorConfigValidation::acceptsHttpsAndToken()
{
    QCOMPARE(CoordinatorConfigValidation::validate(
                 QStringLiteral("https://coord.example/"),
                 QStringLiteral("shared-db"),
                 QString(32, QLatin1Char('a'))),
             QString());
    QCOMPARE(CoordinatorConfigValidation::validate(
                 QStringLiteral("http://127.0.0.1:8765/"),
                 QStringLiteral("shared_db"),
                 QString(32, QLatin1Char('z'))),
             QString());
}

void TestCoordinatorConfigValidation::rejectsCleartextNonLoopback()
{
    QVERIFY(!CoordinatorConfigValidation::validate(
                 QStringLiteral("http://example.org/"),
                 QStringLiteral("shared-db"),
                 QString(32, QLatin1Char('a')))
                 .isEmpty());
}

void TestCoordinatorConfigValidation::rejectsShortToken()
{
    QVERIFY(!CoordinatorConfigValidation::validate(
                 QStringLiteral("https://coord.example/"),
                 QStringLiteral("shared-db"),
                 QStringLiteral("too-short"))
                 .isEmpty());
}

void TestCoordinatorConfigValidation::rejectsBadDatabaseId()
{
    QVERIFY(!CoordinatorConfigValidation::validate(
                 QStringLiteral("https://coord.example/"),
                 QStringLiteral("Bad ID"),
                 QString(32, QLatin1Char('a')))
                 .isEmpty());
}

QTEST_GUILESS_MAIN(TestCoordinatorConfigValidation)
#include "TestCoordinatorConfigValidation.moc"
