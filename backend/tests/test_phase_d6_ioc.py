"""
Phase D6 Tests — IOC Normalization and Validation.

Tests for the canonical IOC representation and SSRF protections.
"""

from __future__ import annotations

import pytest

from app.threat_intel.ioc import (
    IOC,
    IOCType,
    IOCValidationError,
    normalize_ioc,
    normalize_iocs,
    normalize_ipv4,
    normalize_ipv6,
    normalize_domain,
    normalize_url,
    normalize_hash,
    normalize_email,
    is_private_or_reserved_ip,
    extract_iocs_from_email,
)


class TestIOCNormalization:
    """Tests for IOC normalization functions."""
    
    # IPv4
    def test_normalize_ipv4_basic(self):
        assert normalize_ipv4("192.168.1.1") == "192.168.1.1"
        assert normalize_ipv4("001.002.003.004") == "1.2.3.4"
        assert normalize_ipv4("10.0.0.1") == "10.0.0.1"
    
    def test_normalize_ipv4_invalid(self):
        with pytest.raises(ValueError):
            normalize_ipv4("999.999.999.999")
        with pytest.raises(ValueError):
            normalize_ipv4("not.an.ip")
    
    # IPv6
    def test_normalize_ipv6_basic(self):
        assert normalize_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
        assert normalize_ipv6("::1") == "::1"
        assert normalize_ipv6("fe80::1") == "fe80::1"
    
    # Domain
    def test_normalize_domain_basic(self):
        normalized, punycode = normalize_domain("Example.COM")
        assert normalized == "example.com"
        assert punycode is False
    
    def test_normalize_domain_punycode(self):
        normalized, punycode = normalize_domain("xn--pple-43d.com")
        assert normalized == "xn--pple-43d.com"
        assert punycode is True
    
    def test_normalize_domain_idna(self):
        # Unicode domain
        normalized, punycode = normalize_domain("müller.de")
        assert normalized == "xn--mller-kva.de"
        assert punycode is True
    
    def test_normalize_domain_invalid(self):
        with pytest.raises(IOCValidationError):
            normalize_domain("")
        with pytest.raises(IOCValidationError):
            normalize_domain("invalid..domain")
    
    # URL
    def test_normalize_url_basic(self):
        normalized, host = normalize_url("https://example.com/path?query=1")
        assert normalized == "https://example.com/path?query=1"
        assert host == "example.com"
    
    def test_normalize_url_ip_host(self):
        normalized, host = normalize_url("http://192.168.1.1:8080/admin")
        assert "192.168.1.1" in normalized
        assert host == "192.168.1.1"
    
    def test_normalize_url_punycode_host(self):
        normalized, host = normalize_url("https://xn--pple-43d.com/")
        assert normalized == "https://xn--pple-43d.com/"
        assert host == "xn--pple-43d.com"
    
    def test_normalize_url_invalid_scheme(self):
        with pytest.raises(IOCValidationError):
            normalize_url("ftp://example.com")
        with pytest.raises(IOCValidationError):
            normalize_url("javascript:alert(1)")
        with pytest.raises(IOCValidationError):
            normalize_url("data:text/html,<script>")
    
    # Hash
    def test_normalize_hash_md5(self):
        normalized, htype = normalize_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert normalized == "d41d8cd98f00b204e9800998ecf8427e"
        assert htype == "MD5"
    
    def test_normalize_hash_sha1(self):
        normalized, htype = normalize_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert htype == "SHA1"
    
    def test_normalize_hash_sha256(self):
        normalized, htype = normalize_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert htype == "SHA256"
    
    def test_normalize_hash_invalid(self):
        with pytest.raises(IOCValidationError):
            normalize_hash("notahash")
        with pytest.raises(IOCValidationError):
            normalize_hash("d41d8cd98f00b204e9800998ecf8427")  # Too short
    
    # Email
    def test_normalize_email_basic(self):
        normalized, domain = normalize_email("User@Example.COM")
        assert normalized == "User@example.com"
        assert domain == "example.com"
    
    def test_normalize_email_unicode_domain(self):
        normalized, domain = normalize_email("user@müller.de")
        assert domain == "xn--mller-kva.de"
    
    def test_normalize_email_invalid(self):
        with pytest.raises(IOCValidationError):
            normalize_email("notanemail")
        with pytest.raises(IOCValidationError):
            normalize_email("user@")


class TestIOCAutoDetection:
    """Tests for auto-detection of IOC types."""
    
    def test_auto_detect_ipv4(self):
        ioc = normalize_ioc("192.168.1.1")
        assert ioc.ioc_type == IOCType.IPV4
    
    def test_auto_detect_ipv6(self):
        ioc = normalize_ioc("2001:db8::1")
        assert ioc.ioc_type == IOCType.IPV6
    
    def test_auto_detect_url(self):
        ioc = normalize_ioc("https://example.com/path")
        assert ioc.ioc_type == IOCType.URL
    
    def test_auto_detect_hash(self):
        ioc = normalize_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert ioc.ioc_type == IOCType.FILE_HASH
    
    def test_auto_detect_email(self):
        ioc = normalize_ioc("user@example.com")
        assert ioc.ioc_type == IOCType.EMAIL_ADDRESS
    
    def test_auto_detect_domain(self):
        ioc = normalize_ioc("example.com")
        assert ioc.ioc_type == IOCType.DOMAIN


class TestSSRFProtections:
    """Tests for SSRF and private IP protections."""
    
    def test_private_ipv4_blocked(self):
        assert is_private_or_reserved_ip("10.0.0.1") is True
        assert is_private_or_reserved_ip("172.16.0.1") is True
        assert is_private_or_reserved_ip("192.168.1.1") is True
    
    def test_loopback_blocked(self):
        assert is_private_or_reserved_ip("127.0.0.1") is True
        assert is_private_or_reserved_ip("::1") is True
    
    def test_link_local_blocked(self):
        assert is_private_or_reserved_ip("169.254.1.1") is True
        assert is_private_or_reserved_ip("fe80::1") is True
    
    def test_multicast_blocked(self):
        assert is_private_or_reserved_ip("224.0.0.1") is True
        assert is_private_or_reserved_ip("ff02::1") is True
    
    def test_metadata_endpoint_blocked(self):
        assert is_private_or_reserved_ip("169.254.169.254") is True
        assert is_private_or_reserved_ip("169.254.169.253") is True
    
    def test_public_ip_allowed(self):
        assert is_private_or_reserved_ip("8.8.8.8") is False
        assert is_private_or_reserved_ip("1.1.1.1") is False
        assert is_private_or_reserved_ip("2001:4860:4860::8888") is False
    
    def test_private_ip_in_url_flagged(self):
        ioc = normalize_ioc("http://10.0.0.1/admin")
        assert ioc.ioc_type == IOCType.URL
        assert "ip_host=True" in ioc.extraction_context


class TestIOCDeduplication:
    """Tests for IOC batch normalization and deduplication."""
    
    def test_deduplicate_same_ioc(self):
        values = ["192.168.1.1", "192.168.1.1", "10.0.0.1"]
        iocs = normalize_iocs(values)
        assert len(iocs) == 2  # 192.168.1.1 deduplicated
    
    def test_deduplicate_case_insensitive(self):
        values = ["Example.COM", "example.com", "EXAMPLE.COM"]
        iocs = normalize_iocs(values, IOCType.DOMAIN)
        assert len(iocs) == 1
    
    def test_skip_invalid(self):
        values = ["192.168.1.1", "notavalidip", "8.8.8.8"]
        iocs = normalize_iocs(values)
        # Should only have valid IPs
        assert len(iocs) == 2


class TestIOCExtraction:
    """Tests for IOC extraction from emails."""
    
    def test_extract_from_headers(self):
        headers = {
            "received": "from mail.example.com (192.168.1.1) by mx.example.com",
            "from": "user@example.com",
            "reply-to": "reply@phishing-site.xyz",
        }
        iocs = extract_iocs_from_email(headers=headers)
        
        ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
        email_iocs = [i for i in iocs if i.ioc_type == IOCType.EMAIL_ADDRESS]
        
        assert len(ip_iocs) >= 1
        assert any(i.normalized_value == "192.168.1.1" for i in ip_iocs)
        assert len(domain_iocs) >= 1
        assert len(email_iocs) >= 2
    
    def test_extract_urls_from_body(self):
        body_text = "Click here: https://evil-site.xyz/login and http://192.168.1.1/admin"
        body_html = '<a href="https://short.url/abc">link</a>'
        
        iocs = extract_iocs_from_email(
            headers={},
            body_text=body_text,
            body_html=body_html,
        )
        
        url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL]
        assert len(url_iocs) >= 3  # evil-site, IP URL, shortener
        
        # Check shortener detection
        shortener_urls = [u for u in url_iocs if "short.url" in u.normalized_value]
        assert len(shortener_urls) >= 1
    
    def test_extract_hashes_from_attachments(self):
        attachments = [
            {"filename": "doc.pdf", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"filename": "image.png", "sha256": "invalidhash"},
        ]
        
        iocs = extract_iocs_from_email(
            headers={},
            attachments=attachments,
        )
        
        hash_iocs = [i for i in iocs if i.ioc_type == IOCType.FILE_HASH]
        assert len(hash_iocs) == 1
        assert hash_iocs[0].normalized_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestIOCMetadata:
    """Tests for IOC metadata and provenance."""
    
    def test_ioc_cache_key(self):
        ioc = normalize_ioc("192.168.1.1")
        assert ioc.cache_key() == "IPV4:192.168.1.1"
    
    def test_ioc_display_value_preserved(self):
        ioc = normalize_ioc("Example.COM")
        assert ioc.display_value == "Example.COM"
        assert ioc.normalized_value == "example.com"
    
    def test_ioc_source_tracking(self):
        ioc = normalize_ioc(
            "example.com",
            source_location="headers",
            extraction_context="from_address",
        )
        assert ioc.source_location == "headers"
        assert "from_address" in ioc.extraction_context


if __name__ == "__main__":
    pytest.main([__file__, "-v"])