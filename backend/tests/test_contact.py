import pytest

from app.legitimacy.contact import ATS_SENDERS, contact_email_findings, email_auth_findings


# ---------------------------------------------------------------- P1, P2

def statuses(findings):
    return {f.check: f.status for f in findings}


@pytest.mark.parametrize("email, official, p1, p2", [
    ("jane.doe@gmail.com", "coinbase.com", "hit", "clear"),       # P1 counts it, P2 doesn't
    ("jane@proton.me", "coinbase.com", "hit", "clear"),
    ("jane@gmail.com", None, "hit", "clear"),
    ("jane@coinbase.com", "coinbase.com", "clear", "clear"),
    ("jane@careers.coinbase.com", "coinbase.com", "clear", "clear"),
    ("JANE@CoinBase.com", "https://www.coinbase.com", "clear", "clear"),
    ("Jane Doe <jane@stripe.com>", "coinbase.com", "clear", "hit"),
    ("jane@coinbase-talent.net", "coinbase.com", "clear", "clear"),  # lookalike: H3 counts it
    ("jane@c0inbase.com", "coinbase.com", "clear", "clear"),
    ("jane@cоinbase.com", "coinbase.com", "clear", "clear"),     # Unicode domain
    ("no-reply@greenhouse-mail.io", "coinbase.com", "clear", "clear"),
    ("no-reply@us.greenhouse-mail.io", "coinbase.com", "clear", "clear"),
    ("no-reply@hire.lever.co", "coinbase.com", "clear", "clear"),
    ("jobs-noreply@linkedin.com", "coinbase.com", "clear", "clear"),
    ("notifications@ashbyhq.com", None, "clear", "clear"),
    ("jane@stripe.com", None, "clear", "unknown"),
    ("jane@stripe.com", "localhost", "clear", "unknown"),
    ("jane@stripe.com", "http://[coinbase.com", "clear", "unknown"),
])
def test_contact_email(email, official, p1, p2):
    findings = contact_email_findings(email, official_domain=official)
    assert [f.check for f in findings] == ["P1_free_webmail", "P2_email_off_official_domain"]
    assert statuses(findings) == {"P1_free_webmail": p1, "P2_email_off_official_domain": p2}


@pytest.mark.parametrize("email", [
    "", "jane", "jane@", "@coinbase.com", "jane@localhost", "coinbase.com", "jane@http://[x",
])
def test_unreadable_email_is_unknown(email):
    findings = contact_email_findings(email, official_domain="coinbase.com")
    assert [f.status for f in findings] == ["unknown", "unknown"]


def test_contact_email_summaries():
    p1, p2 = contact_email_findings("jane@gmail.com", official_domain="coinbase.com")
    assert p1.evidence[0].summary == "The contact writes from gmail.com, a free webmail service"
    _, p2 = contact_email_findings("jane@stripe.com", official_domain="coinbase.com")
    assert p2.evidence[0].summary == "The contact writes from stripe.com, not coinbase.com"


def test_ats_senders_is_exported():
    assert {"greenhouse.io", "lever.co", "hire.lever.co", "linkedin.com"} <= ATS_SENDERS


# ---------------------------------------------------------------- H6, P3

# Gmail, "Show original": the ARC copy comes first and must not be read as the real header.
GMAIL_PASS = """\
Delivered-To: lucas.candidate@gmail.com
Received: by 2002:a05:7300:6c8b:b0:1a4:2f1e:9e2c with SMTP id m11csp1203912dyc;
        Tue, 3 Nov 2026 09:14:02 -0800 (PST)
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@coinbase.com header.s=google header.b=Qm9vYmFy;
       spf=pass (google.com: domain of recruiting@coinbase.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=recruiting@coinbase.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=coinbase.com
Return-Path: <recruiting@coinbase.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id a1sor123456qkb.12.2026.11.03.09.14.01
Received-SPF: pass (google.com: domain of recruiting@coinbase.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@coinbase.com header.s=google header.b=Qm9vYmFy;
       spf=pass (google.com: domain of recruiting@coinbase.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=recruiting@coinbase.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=coinbase.com
From: Coinbase Recruiting <recruiting@coinbase.com>
Subject: Next steps
"""

# Outlook / Microsoft 365, "View message source": no authserv-id, CRLF line ends.
OUTLOOK_PASS = (
    "Received: from AM6PR04MB5432.eurprd04.prod.outlook.com (2603:10a6:20b:f0::12)\r\n"
    " by DB9PR04MB8301.eurprd04.prod.outlook.com with HTTPS; Tue, 3 Nov 2026 17:14:05 +0000\r\n"
    "Authentication-Results: spf=pass (sender IP is 40.107.22.71)\r\n"
    " smtp.mailfrom=coinbase.com; dkim=pass (signature was verified)\r\n"
    " header.d=coinbase.com;dmarc=pass action=none header.from=coinbase.com;compauth=pass\r\n"
    " reason=100\r\n"
    "Received-SPF: Pass (protection.outlook.com: domain of coinbase.com designates\r\n"
    " 40.107.22.71 as permitted sender) receiver=protection.outlook.com;\r\n"
    " client-ip=40.107.22.71; helo=EUR05-AM6-obe.outbound.protection.outlook.com; pr=C\r\n"
    "From: Coinbase Talent <talent@coinbase.com>\r\n"
)

# Someone spoofing the company's From: address from their own server.
OUTLOOK_SPOOFED = (
    "Authentication-Results: spf=fail (sender IP is 185.234.72.19)\r\n"
    " smtp.mailfrom=coinbase.com; dkim=none (message not signed)\r\n"
    " header.d=none;dmarc=fail action=oreject header.from=coinbase.com;compauth=fail\r\n"
    " reason=000\r\n"
    "Received-SPF: Fail (protection.outlook.com: domain of coinbase.com does not\r\n"
    " designate 185.234.72.19 as permitted sender) receiver=protection.outlook.com;\r\n"
    "From: Coinbase HR <hr@coinbase.com>\r\n"
)

GMAIL_SPOOFED = """\
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning hr@coinbase.com does not designate 185.234.72.19 as permitted sender) smtp.mailfrom=hr@coinbase.com;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=coinbase.com
From: "Coinbase HR" <hr@coinbase.com>
"""

# A real pass, but for the lookalike the scammer owns.
GMAIL_PASS_OTHER_DOMAIN = """\
Authentication-Results: mx.google.com;
       dkim=pass header.i=@coinbase-careers.com header.s=default header.b=Zm9vYmFy;
       spf=pass (google.com: domain of jane@coinbase-careers.com designates 162.241.30.11 as permitted sender) smtp.mailfrom=jane@coinbase-careers.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=coinbase-careers.com
From: Jane Smith <jane@coinbase-careers.com>
"""

# The sender added its own "pass" header before delivery; the provider's header on top says fail.
INJECTED_PASS_BELOW = """\
Authentication-Results: mx.google.com;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=coinbase.com
Received: from mail.attacker.example (mail.attacker.example. [185.234.72.19])
Authentication-Results: mx.attacker.example; dmarc=pass header.from=coinbase.com
From: hr@coinbase.com
"""

# Proton writes one header per method, all with the same authserv-id.
PROTON_SPLIT = """\
Authentication-Results: mail.protonmail.ch; dkim=pass (2048-bit key) header.d=coinbase.com header.i=@coinbase.com header.b="Qm9vYmFy"
Authentication-Results: mail.protonmail.ch; dmarc=pass (p=reject dis=none) header.from=coinbase.com
Authentication-Results: mail.protonmail.ch; spf=pass smtp.mailfrom=coinbase.com
"""

# Yahoo: no space before the comment, and a subdomain From.
YAHOO_SUBDOMAIN = """\
Authentication-Results: atlas210.free.mail.bf1.yahoo.com;
 dkim=pass header.i=@mail.coinbase.com header.s=s1;
 spf=pass smtp.mailfrom=mail.coinbase.com;
 dmarc=pass(p=REJECT) header.from=mail.coinbase.com;
"""

# Pasted with the indentation of the page it was copied from.
INDENTED = """
    Authentication-Results: mx.google.com;
           dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=coinbase.com
    From: hr@coinbase.com
"""

GMAIL_NO_DMARC_POLICY = """\
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of jane@tiny-startup.io designates 1.2.3.4 as permitted sender) smtp.mailfrom=jane@tiny-startup.io;
       dmarc=none header.from=coinbase.com
"""

NO_AUTH_RESULTS = """\
Received: from mail.example.com (mail.example.com [192.0.2.10])
From: hr@coinbase.com
Subject: Offer
"""

ARC_ONLY = """\
ARC-Authentication-Results: i=1; mx.google.com; dmarc=fail header.from=coinbase.com
Authentication-Results-Original: mx.example.com; dmarc=fail header.from=coinbase.com
From: hr@coinbase.com
"""

NO_DMARC_RESULT = """\
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=coinbase.com
"""

NONE_RESULT = """\
Authentication-Results: mx.example.org 1; none
"""

DMARC_WITHOUT_FROM = """\
Authentication-Results: mx.example.org; dmarc=fail
"""


@pytest.mark.parametrize("headers, official, h6, p3", [
    (GMAIL_PASS, "coinbase.com", "clear", "hit"),
    (OUTLOOK_PASS, "coinbase.com", "clear", "hit"),
    (OUTLOOK_SPOOFED, "coinbase.com", "hit", "clear"),
    (GMAIL_SPOOFED, "coinbase.com", "hit", "clear"),
    (GMAIL_PASS_OTHER_DOMAIN, "coinbase.com", "clear", "clear"),
    (INJECTED_PASS_BELOW, "coinbase.com", "hit", "clear"),
    (PROTON_SPLIT, "coinbase.com", "clear", "hit"),
    (YAHOO_SUBDOMAIN, "coinbase.com", "clear", "hit"),
    (INDENTED, "coinbase.com", "hit", "clear"),
    (GMAIL_NO_DMARC_POLICY, "coinbase.com", "clear", "clear"),
    (GMAIL_PASS, "stripe.com", "clear", "clear"),              # a pass, but not for this company
    (OUTLOOK_SPOOFED, "stripe.com", "clear", "clear"),
    (GMAIL_PASS, None, "unknown", "unknown"),
    (OUTLOOK_SPOOFED, "", "unknown", "unknown"),
    (NO_AUTH_RESULTS, "coinbase.com", "unknown", "unknown"),
    (ARC_ONLY, "coinbase.com", "unknown", "unknown"),
    (NO_DMARC_RESULT, "coinbase.com", "unknown", "unknown"),
    (NONE_RESULT, "coinbase.com", "unknown", "unknown"),
    (DMARC_WITHOUT_FROM, "coinbase.com", "unknown", "unknown"),
    ("", "coinbase.com", "unknown", "unknown"),
])
def test_email_auth(headers, official, h6, p3):
    findings = email_auth_findings(headers, official_domain=official)
    assert [f.check for f in findings] == ["H6_dmarc_fail", "P3_dmarc_aligned_pass"]
    assert statuses(findings) == {"H6_dmarc_fail": h6, "P3_dmarc_aligned_pass": p3}


def test_email_auth_summaries():
    h6, _ = email_auth_findings(GMAIL_SPOOFED, official_domain="coinbase.com")
    assert h6.evidence[0].summary == (
        "The email says it's from coinbase.com, but your mail provider's DMARC check failed")
    assert h6.evidence[0].source == "Authentication-Results from mx.google.com"
    _, p3 = email_auth_findings(OUTLOOK_PASS, official_domain="coinbase.com")
    assert p3.evidence[0].summary == "Your mail provider confirmed the email really came from coinbase.com (DMARC pass)"
    assert p3.evidence[0].source == "Authentication-Results"
    h6, p3 = email_auth_findings(GMAIL_PASS_OTHER_DOMAIN, official_domain="coinbase.com")
    assert h6.evidence[0].summary == "DMARC pass for coinbase-careers.com"
