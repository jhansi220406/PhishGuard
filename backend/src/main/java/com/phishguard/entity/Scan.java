package com.phishguard.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scans", indexes = {
    @Index(name = "idx_scans_user_id", columnList = "user_id"),
    @Index(name = "idx_scans_type", columnList = "scan_type"),
    @Index(name = "idx_scans_risk", columnList = "risk_level")
})
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = true)
    private User user;

    @Column(name = "scan_type", nullable = false, length = 20)
    private String scanType; // URL or QR

    @Column(name = "submitted_content", nullable = false, length = 2048)
    private String submittedContent;

    @Column(name = "destination_hostname", length = 255)
    private String destinationHostname;

    @Column(name = "detected_content_type", nullable = false, length = 50)
    private String detectedContentType = "URL";

    @Column(name = "risk_level", nullable = false, length = 30)
    private String riskLevel = "UNKNOWN"; // LOW, MEDIUM, HIGH, UNKNOWN

    @Column(name = "risk_score", nullable = false)
    private Integer riskScore = 0; // 0 to 100

    @Column(name = "threat_provider_status", length = 150)
    private String threatProviderStatus = "Reputation unavailable";

    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt = LocalDateTime.now();

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private List<ScanFinding> findings = new ArrayList<>();

    public Scan() {}

    public void addFinding(ScanFinding finding) {
        findings.add(finding);
        finding.setScan(this);
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }

    public String getSubmittedContent() { return submittedContent; }
    public void setSubmittedContent(String submittedContent) { this.submittedContent = submittedContent; }

    public String getDestinationHostname() { return destinationHostname; }
    public void setDestinationHostname(String destinationHostname) { this.destinationHostname = destinationHostname; }

    public String getDetectedContentType() { return detectedContentType; }
    public void setDetectedContentType(String detectedContentType) { this.detectedContentType = detectedContentType; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public String getThreatProviderStatus() { return threatProviderStatus; }
    public void setThreatProviderStatus(String threatProviderStatus) { this.threatProviderStatus = threatProviderStatus; }

    public LocalDateTime getScannedAt() { return scannedAt; }
    public void setScannedAt(LocalDateTime scannedAt) { this.scannedAt = scannedAt; }

    public List<ScanFinding> getFindings() { return findings; }
    public void setFindings(List<ScanFinding> findings) { this.findings = findings; }
}
