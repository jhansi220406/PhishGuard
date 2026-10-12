package com.phishguard.dto;

public class ScanFindingDto {
    private String indicatorCode;
    private String title;
    private String description;
    private String severity;
    private Integer scoreImpact;

    public ScanFindingDto() {}
    public ScanFindingDto(String indicatorCode, String title, String description, String severity, Integer scoreImpact) {
        this.indicatorCode = indicatorCode;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.scoreImpact = scoreImpact;
    }

    public String getIndicatorCode() { return indicatorCode; }
    public void setIndicatorCode(String indicatorCode) { this.indicatorCode = indicatorCode; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Integer getScoreImpact() { return scoreImpact; }
    public void setScoreImpact(Integer scoreImpact) { this.scoreImpact = scoreImpact; }
}
