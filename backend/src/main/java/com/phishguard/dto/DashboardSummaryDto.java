package com.phishguard.dto;

public class DashboardSummaryDto {
    private long totalScans;
    private long urlScans;
    private long qrScans;
    private long threatsDetected;
    private boolean isDemo = false;

    public DashboardSummaryDto() {}
    public DashboardSummaryDto(long totalScans, long urlScans, long qrScans, long threatsDetected, boolean isDemo) {
        this.totalScans = totalScans;
        this.urlScans = urlScans;
        this.qrScans = qrScans;
        this.threatsDetected = threatsDetected;
        this.isDemo = isDemo;
    }

    public long getTotalScans() { return totalScans; }
    public void setTotalScans(long totalScans) { this.totalScans = totalScans; }

    public long getUrlScans() { return urlScans; }
    public void setUrlScans(long urlScans) { this.urlScans = urlScans; }

    public long getQrScans() { return qrScans; }
    public void setQrScans(long qrScans) { this.qrScans = qrScans; }

    public long getThreatsDetected() { return threatsDetected; }
    public void setThreatsDetected(long threatsDetected) { this.threatsDetected = threatsDetected; }

    public boolean isDemo() { return isDemo; }
    public void setDemo(boolean demo) { isDemo = demo; }
}
