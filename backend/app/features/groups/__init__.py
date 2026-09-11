"""
Feature group extraction modules for VERTEX Forensic Feature Engine.
"""
from app.features.groups.message_basics import extract_message_basics
from app.features.groups.header_signals import extract_header_signals
from app.features.groups.authentication_signals import extract_authentication_signals
from app.features.groups.identity_consistency import extract_identity_consistency
from app.features.groups.relay_path import extract_relay_path
from app.features.groups.ip_infrastructure import extract_ip_infrastructure
from app.features.groups.domain_signals import extract_domain_signals
from app.features.groups.url_signals import extract_url_signals
from app.features.groups.attachment_signals import extract_attachment_signals
from app.features.groups.content_structure import extract_content_structure
from app.features.groups.bec_phish_signals import extract_bec_phish_signals

__all__ = [
    "extract_message_basics",
    "extract_header_signals",
    "extract_authentication_signals",
    "extract_identity_consistency",
    "extract_relay_path",
    "extract_ip_infrastructure",
    "extract_domain_signals",
    "extract_url_signals",
    "extract_attachment_signals",
    "extract_content_structure",
    "extract_bec_phish_signals",
]
