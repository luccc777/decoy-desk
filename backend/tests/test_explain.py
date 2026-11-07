"""The explanation can only describe the verdict: it never changes it and never blocks it."""

import asyncio

from app import llm
from app.rules.engine import Evidence, Fired, Verdict
from app.rules.explain import SCHEMA, explain, facts, template


def verdict(color="red", reason="hard_trigger", fired=None, coverage=0.8):
    fired = fired if fired is not None else [
        Fired(check="H4_domain_seized_or_listed", layer="sender", title="The domain was seized", hard=True,
              points=0, evidence=[Evidence(summary="Its name servers end in .seized.gov")]),
        Fired(check="T3_work_computer_or_admin", layer="sender", title="Asks you to use your work computer",
              hard=False, points=20, evidence=[Evidence(summary="Found in the conversation",
                                                        quote="run it on your work laptop")]),
    ]
    return Verdict(color=color, reason=reason, message="Stop. Don't open or run this on your computer.",
                   score=80, coverage=coverage, fired=fired, unknown=[], table_version=1)


def run(v, complete):
    return asyncio.run(explain(v, complete=complete))


def answer(**over):
    base = {"headline": "This company was taken down by the authorities.",
            "bullets": ["Its website was seized.", "They want you to use your work laptop."],
            "next_step": "Don't run anything they sent and stop replying."}
    return {**base, **over}


def fake(result):
    async def complete(**kwargs):
        assert kwargs["schema"] is SCHEMA and kwargs["model"] == llm.EXPLAIN_MODEL
        assert "<verdict>" in kwargs["user"]
        if isinstance(result, Exception):
            raise result
        return result
    return complete


def test_a_good_answer_is_used():
    e = run(verdict(), fake(answer()))
    assert e.source == "model" and e.headline.startswith("This company")


def test_the_facts_carry_the_evidence_and_the_quote():
    lines = facts(verdict())
    assert lines[0].startswith("[STOP rule] The domain was seized")
    assert '(they wrote: "run it on your work laptop")' in lines[1]


def test_an_answer_that_contradicts_the_color_is_dropped():
    e = run(verdict(), fake(answer(headline="This looks safe, go ahead.")))
    assert e.source == "template"
    assert e.headline == "Stop. Don't open or run this on your computer."


def test_a_green_verdict_cannot_be_called_a_scam():
    v = verdict(color="green", reason="no_flags", fired=[])
    assert run(v, fake(answer(headline="This is a scam."))).source == "template"


def test_model_down_or_wrong_shape_falls_back_to_the_template():
    assert run(verdict(), fake(llm.LLMError("down"))).source == "template"
    assert run(verdict(), fake({"company_name": "BlockNovas"})).source == "template"  # a demo's recorded answer
    assert run(verdict(), fake(answer(bullets=[]))).source == "template"


def test_template_lists_the_red_flags_first_and_says_what_to_do():
    e = template(verdict())
    assert e.bullets[0] == "The domain was seized: Its name servers end in .seized.gov"
    assert e.next_step.startswith("Don't open or run it")


def test_template_explains_low_coverage():
    v = verdict(color="yellow", reason="low_coverage", fired=[], coverage=0.4)
    assert any("40%" in b for b in template(v).bullets)
