import pytest

from app.legitimacy.contact import contact_email_findings, email_auth_findings
from app.legitimacy.lookalike import (
    damerau_levenshtein,
    lookalike_finding,
    lookalike_reason,
    meeting_link_finding,
    off_official_domain_finding,
)
from app.rules.engine import decide, load_table

PUNY_COINBASE = "cоinbase".encode("idna").decode("ascii") + ".com"  # Cyrillic o


# ---------------------------------------------------------------- edit distance

@pytest.mark.parametrize("a, b, expected", [
    ("", "", 0),
    ("", "abc", 3),
    ("abc", "abc", 0),
    ("kitten", "sitting", 3),
    ("coinbase", "conibase", 1),   # one swap
    ("ca", "abc", 2),              # unrestricted Damerau: the optimal-string-alignment variant gives 3
    ("coinbase", "coinbace", 1),
    ("coinbase", "coinbasse", 1),
])
def test_damerau_levenshtein(a, b, expected):
    assert damerau_levenshtein(a, b) == expected
    assert damerau_levenshtein(b, a) == expected


# ---------------------------------------------------------------- lookalike_reason

@pytest.mark.parametrize("candidate, detail", [
    ("c0inbase.com", "(0 for o)"),
    ("coinbase-careers.com", '(adds "careers")'),
    ("careers-coinbase.com", '(adds "careers")'),
    ("coinbase.co", "(.co instead of .com)"),
    ("coinbasehr.com", '(adds "hr")'),
    ("coinbasejobs.com", '(adds "jobs")'),
    ("officialcoinbase.com", '(adds "official")'),
    ("coinbase-inc.com", '(adds "inc")'),
    ("coinbase.com.verify-login.io", "(the site is really verify-login.io)"),
    ("coinbase-login.evil.io", "(the site is really evil.io)"),
    ("login.c0inbase.evil.io", "(the site is really evil.io)"),
    ("coinbase-careers.webflow.io", '(adds "careers")'),
    ("coinbase.webflow.io", "(.webflow.io instead of .com)"),
    ("jobs-at-coinbase.vercel.app", '(adds "jobs-at")'),
    (PUNY_COINBASE, "(Cyrillic о for o)"),
    ("cоinbase.com", "(Cyrillic о for o)"),
    ("cοinbase.com", "(Greek ο for o)"),
    ("coinbäse.com", "(ä for a)"),
    ("c0inbase-careers.com", '(adds "careers", 0 for o)'),
    ("coinbace.com", "(c for s)"),
    ("coinbsae.com", "(a and s swapped)"),
    ("coinbasse.com", "(extra s)"),
    ("conbase.com", "(missing i)"),
    ("coin-base.com", "(extra hyphen)"),
    ("c0inbace.com", "(2 characters off)"),
    ("https://careers.coinbase.co/apply", "(.co instead of .com)"),
    ("jane@c0inbase.com", "(0 for o)"),
    ("https://coinbase.com@evil.io/login", "(the site is really evil.io)"),
    ("https://verify-login.io/coinbase.com/login", "(the page is on verify-login.io)"),
    ("https://sites.google.com/view/coinbase.com-careers", "(the page is on google.com)"),
    ("coin​base.com", "(hidden character)"),
])
def test_lookalikes_of_coinbase(candidate, detail):
    reason = lookalike_reason(candidate, "coinbase.com")
    assert reason is not None
    assert reason.endswith(detail)
    assert "imitates coinbase.com" in reason


@pytest.mark.parametrize("candidate, reference, detail", [
    ("chirne.com", "chime.com", "(rn for m)"),
    ("vvise.com", "wise.com", "(vv for w)"),
    ("paypa1.com", "paypal.com", "(1 for l)"),
    ("comell.edu", "cornell.edu", "(m for rn)"),
    ("gmai1.com", "gmail.com", "(1 for l)"),      # a known contact on webmail
    ("stripe-hiring.com", "https://stripe.com/jobs", '(adds "hiring")'),
])
def test_lookalikes_of_other_references(candidate, reference, detail):
    reason = lookalike_reason(candidate, reference)
    assert reason is not None and reason.endswith(detail)


def test_punycode_reason_shows_what_the_user_sees():
    reason = lookalike_reason(PUNY_COINBASE, "coinbase.com")
    assert reason.startswith(f"{PUNY_COINBASE} (cоinbase.com) imitates coinbase.com")


@pytest.mark.parametrize("candidate, reference", [
    ("careers.coinbase.com", "coinbase.com"),          # a real subdomain
    ("coinbase.com", "coinbase.com"),                  # the official domain itself
    ("https://www.coinbase.com/careers", "coinbase.com"),
    ("jane@coinbase.com", "coinbase.com"),
    ("coinbase.com", "https://careers.coinbase.com/"),
    ("stripe.com", "coinbase.com"),                    # unrelated: C4's job
    ("verify-login.io", "coinbase.com"),
    ("coinbase.zoom.us", "coinbase.com"),              # a company's Zoom vanity host
    ("coinbase.wd1.myworkdayjobs.com", "coinbase.com"),  # its Workday tenant
    ("boards.greenhouse.io/coinbase", "coinbase.com"),   # a bare name in a path is normal
    ("github.com/coinbase", "coinbase.com"),
    ("linkedin.com/company/coinbase", "coinbase.com"),
    ("https://www.google.com/url?q=https://coinbase.com", "coinbase.com"),  # query, not path
    ("lever.co", "clever.com"),                        # a recruiting platform, not a typo
    ("ymail.com", "gmail.com"),                        # webmail providers aren't lookalikes
    ("gitlab.com", "github.com"),
    ("rome.com", "ramp.com"),                          # distance 2 on a 4-letter label is noise
    ("ibn.com", "ibm.com"),                            # labels under 4 letters skip edit distance
    ("coinbaseventures.com", "coinbase.com"),          # glued words count only from the list
    ("notcoinbase.com/x", "coinbase.com"),
    ("", "coinbase.com"),
    ("coinbase-careers.com", ""),
    ("localhost", "coinbase.com"),
    ("1.2.3.4", "coinbase.com"),
    ("http://[c0inbase.com", "coinbase.com"),         # malformed URL
    ("c0inbase.com", "http://[coinbase.com"),
])
def test_not_lookalikes(candidate, reference):
    assert lookalike_reason(candidate, reference) is None


# ---------------------------------------------------------------- H3

def test_h3_hit_has_one_line_per_offending_domain():
    f = lookalike_finding(
        ["coinbase.com", "careers.coinbase.com", "c0inbase.com", "https://c0inbase.com/apply",
         "coinbase-careers.com", "stripe.com", "gmail.com"],
        official_domain="coinbase.com", known_contact_domain=None)
    assert f.check == "H3_lookalike_domain"
    assert f.status == "hit"
    assert [e.summary for e in f.evidence] == [
        "c0inbase.com imitates coinbase.com (0 for o)",
        'coinbase-careers.com imitates coinbase.com (adds "careers")',
    ]


def test_h3_hit_against_the_known_contact():
    f = lookalike_finding(["acme-labs.io", "jane@acrne-labs.io"],
                          official_domain=None, known_contact_domain="acme-labs.io")
    assert f.status == "hit"
    assert f.evidence[0].summary == "acrne-labs.io imitates acme-labs.io (rn for m)"


def test_h3_checks_both_references():
    f = lookalike_finding(["c0inbase.com", "stripe-hr.com"],
                          official_domain="coinbase.com", known_contact_domain="stripe.com")
    assert [e.summary for e in f.evidence] == [
        "c0inbase.com imitates coinbase.com (0 for o)",
        'stripe-hr.com imitates stripe.com (adds "hr")',
    ]


def test_h3_a_reference_is_never_a_lookalike_of_the_other():
    f = lookalike_finding(["coinbase.co"], official_domain="coinbase.com", known_contact_domain="coinbase.co")
    assert f.status == "clear"


@pytest.mark.parametrize("domains", [
    ["coinbase.com", "careers.coinbase.com", "https://www.coinbase.com/careers"],
    ["stripe.com", "gmail.com", "boards.greenhouse.io/coinbase", "https://coinbase.zoom.us/j/1"],
    [],
])
def test_h3_clear(domains):
    f = lookalike_finding(domains, official_domain="coinbase.com", known_contact_domain=None)
    assert f.status == "clear"
    assert f.evidence[0].summary == "No link or email imitates coinbase.com"


@pytest.mark.parametrize("official, known", [(None, None), ("", None), ("not a domain", "localhost")])
def test_h3_unknown_without_a_reference(official, known):
    f = lookalike_finding(["c0inbase.com"], official_domain=official, known_contact_domain=known)
    assert f.status == "unknown"


# ---------------------------------------------------------------- H2

@pytest.mark.parametrize("link, owner", [
    ("https://zoom-us.live/j/88123456789", "Zoom"),
    ("https://us05web-zoom.us.meeting.app/j/88123456789?pwd=abc", "Zoom"),
    ("zoom.us.join-meeting.co/j/1", "Zoom"),
    ("https://joinzoom.app/j/1", "Zoom"),
    ("https://z00m-call.com/j/1", "Zoom"),
    ("https://zoom.us@evil.io/j/1", "Zoom"),
    ("https://​zoom-us.live/j/1", "Zoom"),
    ("https://teams-live.com/l/meetup-join/19%3ameeting", "Microsoft"),
    ("https://msteams.link/l/meetup-join/1", "Microsoft"),
    ("https://ms-teams.app/join", "Microsoft"),
    ("https://teams.microsoft.com.meeting-join.net/l/1", "Microsoft"),
    ("https://google-meet.app/abc-defg-hij", "Google"),
    ("https://meet.google.com.verify.io/abc-defg-hij", "Google"),
    ("https://gmeet.co/abc", "Google"),
    ("https://googlemeet.live/abc", "Google"),
    ("https://webex-meeting.net/meet/jane", "Cisco"),
    ("https://skype-join.com/abc", "Microsoft"),
])
def test_fake_meeting_links(link, owner):
    f = meeting_link_finding([link])
    assert f.check == "H2_fake_meeting_link"
    assert f.status == "hit"
    assert len(f.evidence) == 1
    assert f.evidence[0].summary.endswith(f"but {owner} doesn't own it")


@pytest.mark.parametrize("link", [
    "https://meetup.com/python-sp/events/1",
    "https://zoominfo.com/c/coinbase/1",
    "https://teamsnap.com/team/1",
    "https://meet.google.com/abc-defg-hij",
    "https://us05web.zoom.us/j/88123456789?pwd=abc",
    "https://coinbase.zoom.us/j/1",
    "https://zoom.com/j/1",
    "https://www.zoomgov.com/j/1",
    "https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc",
    "https://teams.live.com/meet/9876543210",
    "https://teams.cloud.microsoft/l/meetup-join/1",
    "https://gov.teams.microsoft.us/l/meetup-join/1",
    "https://acme.webex.com/meet/jane",
    "https://join.skype.com/abc",
    "https://meet.jit.si/acme-interview",
    "https://calendar.google.com/calendar/event?eid=1",
    "https://calendly.com/jane/30min",
    "https://zoomcar.com",
    "https://example.com/zoom.us/j/1",   # the path isn't the host
    "not a link",
    "http://[zoom-us.live/j/1",          # malformed: can't say who owns it
    "",
])
def test_real_or_unrelated_meeting_links(link):
    assert meeting_link_finding([link]).status == "clear"


def test_h2_only_the_fake_link_is_listed():
    f = meeting_link_finding(["https://meet.google.com/abc-defg-hij", "https://zoom-us.live/j/1",
                              "https://zoom-us.live/j/1"])
    assert [e.summary for e in f.evidence] == ["zoom-us.live uses the Zoom name, but Zoom doesn't own it"]


def test_h2_no_links_is_clear():
    assert meeting_link_finding([]).status == "clear"


# ---------------------------------------------------------------- C4

@pytest.mark.parametrize("supplied, status", [
    (["stripe.com"], "hit"),
    (["https://www.stripe.com", "jane@coinbase.com"], "hit"),
    (["coinbase.com"], "clear"),
    (["https://careers.coinbase.com/", "coinbase.com", "jane@coinbase.com"], "clear"),
    (["c0inbase.com"], "clear"),                                 # H3's job, not C4's
    (["coinbase.com.verify-login.io", "verify-login.io"], "clear"),  # same site as a lookalike
    (["coinbase.com", "gmail.com"], "clear"),
    (["gmail.com"], "unknown"),                                  # webmail says nothing here
    (["greenhouse.io", "hire.lever.co"], "unknown"),             # nor do recruiting platforms
    ([], "unknown"),
    (["not a domain", "", "http://[stripe.com"], "unknown"),
])
def test_off_official_domain(supplied, status):
    f = off_official_domain_finding(supplied, official_domain="coinbase.com")
    assert f.check == "C4_off_official_domain"
    assert f.status == status


def test_c4_hit_lists_each_unrelated_domain_once():
    f = off_official_domain_finding(["stripe.com", "https://stripe.com/about", "acme.io", "c0inbase.com"],
                                    official_domain="coinbase.com")
    assert [e.summary for e in f.evidence] == [
        "stripe.com isn't the company's official domain, coinbase.com",
        "acme.io isn't the company's official domain, coinbase.com",
    ]


def test_c4_when_the_company_is_itself_a_platform():
    f = off_official_domain_finding(["https://www.greenhouse.io", "gmail.com"], official_domain="greenhouse.io")
    assert f.status == "clear"


@pytest.mark.parametrize("official", [None, "", "localhost"])
def test_c4_unknown_without_an_official_domain(official):
    assert off_official_domain_finding(["stripe.com"], official_domain=official).status == "unknown"


# ---------------------------------------------------------------- wiring

def test_every_finding_uses_a_check_from_the_table():
    findings = [
        lookalike_finding(["c0inbase.com"], official_domain="coinbase.com", known_contact_domain=None),
        meeting_link_finding(["https://zoom-us.live/j/1"]),
        off_official_domain_finding(["stripe.com"], official_domain="coinbase.com"),
        *contact_email_findings("jane@gmail.com", official_domain="coinbase.com"),
        *email_auth_findings("Authentication-Results: mx.google.com; dmarc=fail header.from=coinbase.com",
                             official_domain="coinbase.com"),
    ]
    table = load_table()
    assert {f.check for f in findings} <= set(table.checks)
    verdict = decide(findings, {"company", "contact_email", "email_headers", "meeting_link"})
    assert verdict.color == "red"
    assert {"H2_fake_meeting_link", "H3_lookalike_domain", "H6_dmarc_fail"} <= {f.check for f in verdict.fired}
