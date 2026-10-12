package com.phishguard.dto;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class ScanResponse {
    private Long id;
    private String scanType;
    private String submittedContent;
    private String destinationHostname;
    private String detectedContentType;
    private String riskLevel;
    private Integer riskScore;
    private String threatProviderStatus;
    private LocalDateTime scannedAt;
    private List<ScanFindingDto> findings = new ArrayList<>();
    private List<String> recommendations = new ArrayList<>();

    public ScanResponse() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

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

    public List<ScanFindingDto> getFindings() { return findings; }
    public void setFindings(List<ScanFindingDto> findings) { this.findings = findings; }

    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
}
