package com.phishguard.service;

import com.phishguard.dto.ScanFindingDto;
import com.phishguard.dto.ScanResponse;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.regex.Pattern;

@Service
public class QrProcessingService {

    private final UrlAnalysisService urlAnalysisService;

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^(?:mailto:)?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URL_STRUCTURE_PATTERN = Pattern.compile(
            "^(?:https?://|www\\.)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?:/.*)?$", Pattern.CASE_INSENSITIVE
    );

    public QrProcessingService(UrlAnalysisService urlAnalysisService) {
        this.urlAnalysisService = urlAnalysisService;
    }

    /**
     * Inspects QR code string, determines payload type, and routes accordingly
     */
    public ScanResponse processQrPayload(String rawContent) {
        if (rawContent == null || rawContent.trim().isEmpty()) {
            ScanResponse emptyRes = new ScanResponse();
            emptyRes.setScanType("QR");
            emptyRes.setDetectedContentType("PLAIN_TEXT");
            emptyRes.setRiskLevel("UNKNOWN");
            emptyRes.setRiskScore(0);
            emptyRes.setThreatProviderStatus("Empty QR code payload");
            emptyRes.setScannedAt(LocalDateTime.now());
            return emptyRes;
        }

        String content = rawContent.trim();
        String contentType = detectContentType(content);

        if ("URL".equals(contentType)) {
            // Forward directly to deterministic URL analyzer
            ScanResponse response = urlAnalysisService.analyzeUrl(content);
            response.setScanType("QR");
            response.setDetectedContentType("URL");
            return response;
        }

        // Non-URL Payloads (Plain Text, Email, Phone, WiFi, vCard Contact)
        ScanResponse response = new ScanResponse();
        response.setScanType("QR");
        response.setSubmittedContent(urlAnalysisService.sanitizeForStorage(content));
        response.setDetectedContentType(contentType);
        response.setScannedAt(LocalDateTime.now());
        response.setThreatProviderStatus("Non-URL Payload (Not applicable for web reputation)");

        switch (contentType) {
            case "EMAIL" -> {
                response.setRiskLevel("LOW");
                response.setRiskScore(10);
                response.setDestinationHostname("email-action");
                response.getFindings().add(new ScanFindingDto(
                        "QR_EMAIL_PAYLOAD",
                        "Email Dispatcher Payload",
                        "This QR code triggers a mail compose action. Ensure you recognize the destination recipient before sending messages.",
                        "INFO",
                        10
                ));
                response.getRecommendations().add("Verify the recipient email address carefully before dispatching messages.");
            }
            case "PHONE" -> {
                response.setRiskLevel("LOW");
                response.setRiskScore(10);
                response.setDestinationHostname("telephone-dialer");
                response.getFindings().add(new ScanFindingDto(
                        "QR_TELEPHONE_PAYLOAD",
                        "Telephone Dialing Payload",
                        "This QR code initiates a phone call. Check for toll or premium rate phone numbers.",
                        "INFO",
                        10
                ));
                response.getRecommendations().add("Do not place calls to unknown foreign or premium telephone numbers.");
            }
            case "WIFI" -> {
                response.setRiskLevel("MEDIUM");
                response.setRiskScore(30);
                response.setDestinationHostname("wifi-network");
                response.getFindings().add(new ScanFindingDto(
                        "QR_WIFI_CONFIG",
                        "Wi-Fi Network Configuration Payload",
                        "This QR code automatically provisions a Wi-Fi connection. Connecting to rogue Wi-Fi access points exposes traffic to Man-in-the-Middle interception.",
                        "MEDIUM",
                        30
                ));
                response.getRecommendations().add("Only connect to known, trusted enterprise or home wireless networks.");
            }
            case "CONTACT" -> {
                response.setRiskLevel("LOW");
                response.setRiskScore(5);
                response.setDestinationHostname("vcard-contact");
                response.getFindings().add(new ScanFindingDto(
                        "QR_VCARD_CONTACT",
                        "Contact Card (vCard) Payload",
                        "This QR code provides contact card information to add to an address book.",
                        "INFO",
                        5
                ));
                response.getRecommendations().add("Review contact details and associated links before saving to your device.");
            }
            default -> {
                // Plain Text
                response.setRiskLevel("LOW");
                response.setRiskScore(0);
                response.setDestinationHostname("plain-text");
                response.getFindings().add(new ScanFindingDto(
                        "QR_PLAIN_TEXT",
                        "Plain Text Message",
                        "This QR code contains textual data rather than a website link or device command.",
                        "INFO",
                        0
                ));
                response.getRecommendations().add("Verify text authenticity. Never execute unverified script commands or shell snippets.");
            }
        }

        return response;
    }

    private String detectContentType(String content) {
        String lower = content.toLowerCase();

        if (lower.startsWith("http://") || lower.startsWith("https://") || URL_STRUCTURE_PATTERN.matcher(content).matches()) {
            return "URL";
        }
        if (lower.startsWith("mailto:") || EMAIL_PATTERN.matcher(content).matches()) {
            return "EMAIL";
        }
        if (lower.startsWith("tel:")) {
            return "PHONE";
        }
        if (lower.startsWith("wifi:")) {
            return "WIFI";
        }
        if (lower.startsWith("begin:vcard") || lower.startsWith("mecard:")) {
            return "CONTACT";
        }

        return "PLAIN_TEXT";
    }
}
