"""What a user submits. Every field is optional; the rules table decides which checks apply."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class LinkedInAnswers(BaseModel):
    """What the user saw on the contact's LinkedIn profile (we don't scrape LinkedIn)."""

    model_config = ConfigDict(extra="forbid")

    profile_under_6_months: Optional[bool] = None
    has_any_verification: Optional[bool] = None
    workplace_verified_here: Optional[bool] = None


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    company_name: Optional[str] = Field(None, max_length=200)
    company_website: Optional[str] = Field(None, max_length=500)  # what the sender says the site is
    job_title: Optional[str] = Field(None, max_length=300)
    job_url: Optional[str] = Field(None, max_length=1000)
    contact_email: Optional[str] = Field(None, max_length=320)
    email_headers: Optional[str] = Field(None, max_length=100_000)
    meeting_link: Optional[str] = Field(None, max_length=1000)
    conversation: Optional[str] = Field(None, max_length=50_000)
    repo_url: Optional[str] = Field(None, max_length=1000)
    github_handle: Optional[str] = Field(None, max_length=100)
    known_contact_domain: Optional[str] = Field(None, max_length=255)  # the real domain of someone you know
    linkedin: Optional[LinkedInAnswers] = None

    def inputs(self) -> set[str]:
        """Input kinds for the rules engine. "file" and "detonation" are added by the pipeline."""
        kinds = set()
        if self.company_name or self.company_website:
            kinds.add("company")
        if self.job_title or self.job_url:
            kinds.add("job")
        if self.linkedin and any(v is not None for v in self.linkedin.model_dump().values()):
            kinds.add("linkedin_answers")
        simple = {
            "contact_email": "contact_email", "email_headers": "email_headers",
            "meeting_link": "meeting_link", "conversation": "conversation",
            "repo_url": "repo", "github_handle": "github_handle",
        }
        kinds |= {kind for field, kind in simple.items() if getattr(self, field)}
        return kinds
