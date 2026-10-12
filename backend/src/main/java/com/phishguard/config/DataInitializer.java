package com.phishguard.config;

import com.phishguard.entity.QuizResult;
import com.phishguard.entity.Scan;
import com.phishguard.entity.ScanFinding;
import com.phishguard.entity.User;
import com.phishguard.repository.QuizResultRepository;
import com.phishguard.repository.ScanRepository;
import com.phishguard.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final ScanRepository scanRepository;
    private final QuizResultRepository quizResultRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository,
                           ScanRepository scanRepository,
                           QuizResultRepository quizResultRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.scanRepository = scanRepository;
        this.quizResultRepository = quizResultRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        User analyst = seedUserIfMissing();
        seedScansIfEmpty(analyst);
    }

    private User seedUserIfMissing() {
        return userRepository.findByEmail("analyst@phishguard.security")
                .orElseGet(() -> {
                    log.info("Seeding initial security analyst demo account...");
                    User user = new User(
                            "Security Analyst",
                            "analyst@phishguard.security",
                            passwordEncoder.encode("PhishGuard@2026"),
                            "ROLE_ANALYST"
                    );
                    return userRepository.save(user);
                });
    }

    private void seedScansIfEmpty(User user) {
        if (scanRepository.count() > 0) {
            return;
        }

        log.info("Seeding sample threat scans and realistic demonstration data...");

        // Sample 1: Lookalike Domain Phishing Attempt
        Scan scan1 = new Scan();
        scan1.setUser(user);
        scan1.setScanType("URL");
        scan1.setSubmittedContent("http://paypa1-security.account-update.tk/verify?r=token");
        scan1.setDestinationHostname("paypa1-security.account-update.tk");
        scan1.setDetectedContentType("URL");
        scan1.setRiskLevel("HIGH");
        scan1.setRiskScore(85);
        scan1.setThreatProviderStatus("Reputation service unconfigured (Fallback mode)");
        scan1.setScannedAt(LocalDateTime.now().minusHours(2));
        scan1.addFinding(new ScanFinding("LOOKALIKE_DOMAIN", "Brand Impersonation Target (PAYPAL)", "Deceptive domain mimicking PayPal brand.", "HIGH", 40));
        scan1.addFinding(new ScanFinding("SUSPICIOUS_TLD", "High-Risk Top-Level Domain (.tk)", "Disposable TLD associated with phishing campaigns.", "MEDIUM", 25));
        scan1.addFinding(new ScanFinding("INSECURE_HTTP", "Cleartext HTTP Transmission", "No SSL/TLS transport encryption active.", "LOW", 15));
        scanRepository.save(scan1);

        // Sample 2: Raw IP Hostname Credential Harvester
        Scan scan2 = new Scan();
        scan2.setUser(user);
        scan2.setScanType("URL");
        scan2.setSubmittedContent("http://192.168.0.12/webscr/login.php");
        scan2.setDestinationHostname("192.168.0.12");
        scan2.setDetectedContentType("URL");
        scan2.setRiskLevel("HIGH");
        scan2.setRiskScore(75);
        scan2.setThreatProviderStatus("Reputation service unconfigured (Fallback mode)");
        scan2.setScannedAt(LocalDateTime.now().minusHours(5));
        scan2.addFinding(new ScanFinding("IP_HOSTNAME", "Raw IP Hostname Detected", "Direct IP used instead of registered domain.", "CRITICAL", 45));
        scan2.addFinding(new ScanFinding("CREDENTIAL_TARGETING_KEYWORD", "Sensitive Authentication Keywords", "Path contains sensitive 'login' keyword.", "MEDIUM", 20));
        scanRepository.save(scan2);

        // Sample 3: Legitimate Academic Portal
        Scan scan3 = new Scan();
        scan3.setUser(user);
        scan3.setScanType("URL");
        scan3.setSubmittedContent("https://portal.myuniversity.edu/login");
        scan3.setDestinationHostname("portal.myuniversity.edu");
        scan3.setDetectedContentType("URL");
        scan3.setRiskLevel("LOW");
        scan3.setRiskScore(10);
        scan3.setThreatProviderStatus("Clean");
        scan3.setScannedAt(LocalDateTime.now().minusDays(1));
        scanRepository.save(scan3);

        // Sample 4: Malicious Parking QR Code Overlay (Quishing)
        Scan scan4 = new Scan();
        scan4.setUser(user);
        scan4.setScanType("QR");
        scan4.setSubmittedContent("http://city-meter-pay.quick-check.xyz/charge");
        scan4.setDestinationHostname("city-meter-pay.quick-check.xyz");
        scan4.setDetectedContentType("URL");
        scan4.setRiskLevel("HIGH");
        scan4.setRiskScore(70);
        scan4.setThreatProviderStatus("Reputation service unconfigured (Fallback mode)");
        scan4.setScannedAt(LocalDateTime.now().minusDays(2));
        scan4.addFinding(new ScanFinding("SUSPICIOUS_TLD", "High-Risk Top-Level Domain (.xyz)", "Low cost disposable TLD.", "MEDIUM", 25));
        scan4.addFinding(new ScanFinding("INSECURE_HTTP", "Cleartext HTTP Transmission", "Missing transport layer security.", "LOW", 15));
        scanRepository.save(scan4);

        // Sample 5: Legitimate Contact QR Code
        Scan scan5 = new Scan();
        scan5.setUser(user);
        scan5.setScanType("QR");
        scan5.setSubmittedContent("BEGIN:VCARD\nVERSION:3.0\nFN:Alex Vance\nEMAIL:alex@security.edu\nEND:VCARD");
        scan5.setDestinationHostname("vcard-contact");
        scan5.setDetectedContentType("CONTACT");
        scan5.setRiskLevel("LOW");
        scan5.setRiskScore(5);
        scan5.setThreatProviderStatus("Non-URL Payload");
        scan5.setScannedAt(LocalDateTime.now().minusDays(3));
        scan5.addFinding(new ScanFinding("QR_VCARD_CONTACT", "Contact Card (vCard) Payload", "Standard business card payload.", "INFO", 5));
        scanRepository.save(scan5);

        // Seed initial sample quiz result
        QuizResult qr = new QuizResult(user, 1L, 4, 4);
        quizResultRepository.save(qr);

        log.info("Demo database seeded successfully with 5 sample scans and quiz results.");
    }
}
