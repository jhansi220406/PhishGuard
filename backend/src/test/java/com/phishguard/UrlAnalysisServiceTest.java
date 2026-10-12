package com.phishguard;

import com.phishguard.dto.ScanFindingDto;
import com.phishguard.dto.ScanResponse;
import com.phishguard.service.UrlAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UrlAnalysisServiceTest {

    private UrlAnalysisService service;

    @BeforeEach
    void setUp() {
        service = new UrlAnalysisService();
    }

    @Test
    @DisplayName("Legitimate domain should be classified as LOW risk")
    void testLegitimateDomain() {
        ScanResponse response = service.analyzeUrl("https://www.google.com");

        assertEquals("LOW", response.getRiskLevel());
        assertTrue(response.getRiskScore() < 30, "Risk score should be below 30");
        assertEquals("www.google.com", response.getDestinationHostname());
        assertNotNull(response.getRecommendations());
    }

    @Test
    @DisplayName("Lookalike brand domain with bad TLD should be classified as HIGH risk")
    void testLookalikeDomainWithSuspiciousTld() {
        ScanResponse response = service.analyzeUrl("http://paypal-verification-account.tk/login");

        assertEquals("HIGH", response.getRiskLevel());
        assertTrue(response.getRiskScore() >= 70, "Risk score should be high");

        boolean hasLookalike = response.getFindings().stream()
                .anyMatch(f -> "LOOKALIKE_DOMAIN".equals(f.getIndicatorCode()));
        boolean hasSuspiciousTld = response.getFindings().stream()
                .anyMatch(f -> "SUSPICIOUS_TLD".equals(f.getIndicatorCode()));

        assertTrue(hasLookalike, "Should detect brand lookalike");
        assertTrue(hasSuspiciousTld, "Should detect high-risk .tk TLD");
    }

    @Test
    @DisplayName("Raw IPv4 hostname should trigger CRITICAL IP indicator and HIGH risk")
    void testRawIpHostname() {
        ScanResponse response = service.analyzeUrl("http://192.168.1.100/admin/login.php");

        assertEquals("HIGH", response.getRiskLevel());
        boolean hasIp = response.getFindings().stream()
                .anyMatch(f -> "IP_HOSTNAME".equals(f.getIndicatorCode()));
        assertTrue(hasIp, "Should trigger IP_HOSTNAME indicator");
    }

    @Test
    @DisplayName("RFC 3986 user-info @ trick should trigger AT_SYMBOL_TRICK")
    void testAtSymbolDeception() {
        ScanResponse response = service.analyzeUrl("http://google.com@phishing-landing-host.com/account");

        boolean hasAtTrick = response.getFindings().stream()
                .anyMatch(f -> "AT_SYMBOL_TRICK".equals(f.getIndicatorCode()));
        assertTrue(hasAtTrick, "Should trigger AT_SYMBOL_TRICK indicator");
    }

    @Test
    @DisplayName("Excessive subdomain depth should trigger EXCESSIVE_SUBDOMAINS")
    void testExcessiveSubdomains() {
        ScanResponse response = service.analyzeUrl("https://login.security.update.account.suspicious-domain.com/auth");

        boolean hasSubdomains = response.getFindings().stream()
                .anyMatch(f -> "EXCESSIVE_SUBDOMAINS".equals(f.getIndicatorCode()));
        assertTrue(hasSubdomains, "Should detect nested subdomains");
    }

    @Test
    @DisplayName("Sensitive credentials in query parameters should be redacted for storage")
    void testPrivacyConsciousSanitization() {
        String raw = "https://example.com/login?token=secret123&user=admin&password=MyPassword!";
        String sanitized = service.sanitizeForStorage(raw);

        assertFalse(sanitized.contains("secret123"), "Token value should be redacted");
        assertFalse(sanitized.contains("MyPassword!"), "Password value should be redacted");
        assertTrue(sanitized.contains("[REDACTED]"), "Should contain redacted placeholder");
    }

    @Test
    @DisplayName("Empty or null input should be safely handled without throwing exception")
    void testEmptyInputHandling() {
        ScanResponse res1 = service.analyzeUrl("");
        assertEquals("UNKNOWN", res1.getRiskLevel());

        ScanResponse res2 = service.analyzeUrl(null);
        assertEquals("UNKNOWN", res2.getRiskLevel());
    }
}
