package com.phishguard.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DashboardActivityDto {
    private List<ScanResponse> recentScans = new ArrayList<>();
    private Map<String, Long> riskDistribution = new HashMap<>();
    private List<TimelinePoint> timeline = new ArrayList<>();
    private List<IndicatorCount> topIndicators = new ArrayList<>();

    public static class TimelinePoint {
        private String date;
        private long urlCount;
        private long qrCount;

        public TimelinePoint() {}
        public TimelinePoint(String date, long urlCount, long qrCount) {
            this.date = date;
            this.urlCount = urlCount;
            this.qrCount = qrCount;
        }

        public String getDate() { return date; }
        public void setDate(String date) { this.date = date; }
        public long getUrlCount() { return urlCount; }
        public void setUrlCount(long urlCount) { this.urlCount = urlCount; }
        public long getQrCount() { return qrCount; }
        public void setQrCount(long qrCount) { this.qrCount = qrCount; }
    }

    public static class IndicatorCount {
        private String code;
        private long count;

        public IndicatorCount() {}
        public IndicatorCount(String code, long count) {
            this.code = code;
            this.count = count;
        }

        public String getCode() { return code; }
        public void setCode(String code) { this.code = code; }
        public long getCount() { return count; }
        public void setCount(long count) { this.count = count; }
    }

    public DashboardActivityDto() {}

    public List<ScanResponse> getRecentScans() { return recentScans; }
    public void setRecentScans(List<ScanResponse> recentScans) { this.recentScans = recentScans; }

    public Map<String, Long> getRiskDistribution() { return riskDistribution; }
    public void setRiskDistribution(Map<String, Long> riskDistribution) { this.riskDistribution = riskDistribution; }

    public List<TimelinePoint> getTimeline() { return timeline; }
    public void setTimeline(List<TimelinePoint> timeline) { this.timeline = timeline; }

    public List<IndicatorCount> getTopIndicators() { return topIndicators; }
    public void setTopIndicators(List<IndicatorCount> topIndicators) { this.topIndicators = topIndicators; }
}
