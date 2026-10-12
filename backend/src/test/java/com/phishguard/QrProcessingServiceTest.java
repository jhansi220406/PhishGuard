package com.phishguard;

import com.phishguard.dto.ScanResponse;
import com.phishguard.service.QrProcessingService;
import com.phishguard.service.UrlAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QrProcessingServiceTest {

    private QrProcessingService qrService;

    @BeforeEach
    void setUp() {
        UrlAnalysisService urlService = new UrlAnalysisService();
        qrService = new QrProcessingService(urlService);
    }

    @Test
    @DisplayName("QR code containing web URL should be classified as URL and scanned")
    void testUrlPayloadInQr() {
        ScanResponse res = qrService.processQrPayload("https://myuniversity.edu/welcome");

        assertEquals("QR", res.getScanType());
        assertEquals("URL", res.getDetectedContentType());
        assertEquals("LOW", res.getRiskLevel());
    }

    @Test
    @DisplayName("QR code containing plain text message should not be labeled as safe website")
    void testPlainTextPayloadInQr() {
        ScanResponse res = qrService.processQrPayload("Meeting tomorrow at room 302, please bring your ID.");

        assertEquals("PLAIN_TEXT", res.getDetectedContentType());
        assertEquals("QR", res.getScanType());
        assertTrue(res.getFindings().stream().anyMatch(f -> "QR_PLAIN_TEXT".equals(f.getIndicatorCode())));
    }

    @Test
    @DisplayName("QR code containing mailto should be identified as EMAIL")
    void testEmailPayloadInQr() {
        ScanResponse res = qrService.processQrPayload("mailto:support@service.com?subject=Help");

        assertEquals("EMAIL", res.getDetectedContentType());
        assertTrue(res.getFindings().stream().anyMatch(f -> "QR_EMAIL_PAYLOAD".equals(f.getIndicatorCode())));
    }

    @Test
    @DisplayName("QR code containing WiFi network config should be identified as WIFI")
    void testWifiPayloadInQr() {
        ScanResponse res = qrService.processQrPayload("WIFI:S:GuestNetwork;T:WPA;P:GuestPass123;;");

        assertEquals("WIFI", res.getDetectedContentType());
        assertEquals("MEDIUM", res.getRiskLevel());
        assertTrue(res.getFindings().stream().anyMatch(f -> "QR_WIFI_CONFIG".equals(f.getIndicatorCode())));
    }

    @Test
    @DisplayName("QR code containing vCard should be identified as CONTACT")
    void testContactPayloadInQr() {
        ScanResponse res = qrService.processQrPayload("BEGIN:VCARD\nVERSION:3.0\nN:Smith;John\nTEL:555-1234\nEND:VCARD");

        assertEquals("CONTACT", res.getDetectedContentType());
        assertTrue(res.getFindings().stream().anyMatch(f -> "QR_VCARD_CONTACT".equals(f.getIndicatorCode())));
    }
}
