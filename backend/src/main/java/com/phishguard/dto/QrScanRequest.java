package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class QrScanRequest {

    @NotBlank(message = "Decoded QR content is required")
    @Size(max = 4096, message = "Payload exceeds maximum length")
    private String content;

    private String scanType = "QR";

    public QrScanRequest() {}
    public QrScanRequest(String content, String scanType) {
        this.content = content;
        this.scanType = scanType != null ? scanType : "QR";
    }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }
}
