/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "gui/remote/CoordinatorByteLimits.h"
#include "gui/remote/CoordinatorConfigValidation.h"

#include <QCryptographicHash>
#include <QTest>

class TestCoordinatorConfigValidation : public QObject
{
    Q_OBJECT
private slots:
    void acceptsHttpsAndToken();
    void rejectsCleartextNonLoopback();
    void rejectsShortToken();
    void rejectsBadDatabaseId();
    void rejectsNonPrintableToken();
    void acceptsLeaseResponse();
    void rejectsMalformedLeaseResponse();
    void validatesRevisionRules();
    void matchesPublishAcknowledgement();
    void matchesDownloadedCiphertext();
    void byteLimitsMatchKeySafeCaps();
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

void TestCoordinatorConfigValidation::rejectsNonPrintableToken()
{
    QString token = QString(32, QLatin1Char('a'));
    token[8] = QLatin1Char('\t');
    QVERIFY(!CoordinatorConfigValidation::validate(
                 QStringLiteral("https://coord.example/"),
                 QStringLiteral("shared-db"),
                 token)
                 .isEmpty());
}

void TestCoordinatorConfigValidation::acceptsLeaseResponse()
{
    const QByteArray token = QByteArray(64, 'a');
    const QByteArray body =
        QByteArrayLiteral("{\"token\":\"") + token + QByteArrayLiteral("\",\"revision\":\"0\"}");
    CoordinatorConfigValidation::LeaseFields fields;
    QVERIFY(CoordinatorConfigValidation::parseLeaseResponse(body, &fields));
    QCOMPARE(fields.token, token);
    QCOMPARE(fields.revision, QByteArrayLiteral("0"));
}

void TestCoordinatorConfigValidation::rejectsMalformedLeaseResponse()
{
    CoordinatorConfigValidation::LeaseFields fields;
    QVERIFY(!CoordinatorConfigValidation::parseLeaseResponse(
        QByteArrayLiteral("{\"token\":\"short\",\"revision\":\"0\"}"), &fields));
    QVERIFY(!CoordinatorConfigValidation::parseLeaseResponse(
        QByteArrayLiteral("not-json"), &fields));
    QVERIFY(!CoordinatorConfigValidation::parseLeaseResponse(
        QByteArrayLiteral("{\"token\":\"") + QByteArray(64, 'A')
            + QByteArrayLiteral("\",\"revision\":\"0\"}"),
        &fields));
}

void TestCoordinatorConfigValidation::validatesRevisionRules()
{
    QVERIFY(CoordinatorConfigValidation::isValidRevision(QByteArrayLiteral("0")));
    QVERIFY(CoordinatorConfigValidation::isValidRevision(QByteArray(64, 'b')));
    QVERIFY(!CoordinatorConfigValidation::isValidRevision(QByteArrayLiteral("1")));
    QVERIFY(!CoordinatorConfigValidation::isValidRevision(QByteArray(63, 'c')));
    QVERIFY(!CoordinatorConfigValidation::isValidLeaseToken(QByteArrayLiteral("0")));
}

void TestCoordinatorConfigValidation::matchesPublishAcknowledgement()
{
    const QByteArray rev = QByteArray(64, 'd');
    const QByteArray body =
        QByteArrayLiteral("{\"revision\":\"") + rev + QByteArrayLiteral("\"}");
    QVERIFY(CoordinatorConfigValidation::matchesPublishAck(body, '"' + rev + '"', rev));
    QVERIFY(!CoordinatorConfigValidation::matchesPublishAck(body, '"' + rev + '"', QByteArray(64, 'e')));
    QVERIFY(!CoordinatorConfigValidation::matchesPublishAck(body, rev, rev)); // etag must be quoted
    QVERIFY(!CoordinatorConfigValidation::matchesPublishAck(
        QByteArrayLiteral("{\"revision\":\"0\"}"), "\"0\"", QByteArrayLiteral("0")));
}

void TestCoordinatorConfigValidation::matchesDownloadedCiphertext()
{
    const QByteArray ciphertext = QByteArrayLiteral("kdbx-bytes-for-download-check");
    const QByteArray rev =
        QCryptographicHash::hash(ciphertext, QCryptographicHash::Sha256).toHex();
    QVERIFY(CoordinatorConfigValidation::matchesDownloadedContent(
        ciphertext, '"' + rev + '"', rev));
    QVERIFY(!CoordinatorConfigValidation::matchesDownloadedContent(
        ciphertext, '"' + rev + '"', QByteArray(64, 'f')));
    QVERIFY(!CoordinatorConfigValidation::matchesDownloadedContent(
        ciphertext, rev, rev)); // etag must be quoted
    QVERIFY(!CoordinatorConfigValidation::matchesDownloadedContent(
        QByteArray(), '"' + rev + '"', rev));
    QVERIFY(!CoordinatorConfigValidation::matchesDownloadedContent(
        ciphertext + 'x', '"' + rev + '"', rev));
}

void TestCoordinatorConfigValidation::byteLimitsMatchKeySafeCaps()
{
    QCOMPARE(CoordinatorByteLimits::MaxKdbxBytes, 64LL * 1024 * 1024);
    QCOMPARE(CoordinatorByteLimits::MaxControlBytes, 16LL * 1024);
    QVERIFY(CoordinatorByteLimits::MaxControlBytes < CoordinatorByteLimits::MaxKdbxBytes);
}

QTEST_GUILESS_MAIN(TestCoordinatorConfigValidation)
#include "TestCoordinatorConfigValidation.moc"
