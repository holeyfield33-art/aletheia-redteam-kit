"""Website audit package for route and UI interaction checks."""

from .config import AuthStep, AuthBypassTarget, PromptInjectionTest, WebAuditConfig


def run_website_audit(config: WebAuditConfig):
	from .runner import run_website_audit as _run_website_audit

	return _run_website_audit(config)

__all__ = [
	"AuthBypassTarget",
	"AuthStep",
	"PromptInjectionTest",
	"WebAuditConfig",
	"run_website_audit",
]
