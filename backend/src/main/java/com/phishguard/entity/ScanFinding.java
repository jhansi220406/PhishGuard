package com.phishguard.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

@Entity
@Table(name = "scan_findings")
public class ScanFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    @JsonBackReference
    private Scan scan;

    @Column(name = "indicator_code", nullable = false, length = 80)
    private String indicatorCode;

    @Column(nullable = false, length = 150)
    private String title;

    @Column(nullable = false, length = 1000)
    private String description;

    @Column(nullable = false, length = 30)
    private String severity; // INFO, LOW, MEDIUM, HIGH, CRITICAL

    @Column(name = "score_impact")
    private Integer scoreImpact = 0;

    public ScanFinding() {}

    public ScanFinding(String indicatorCode, String title, String description, String severity, Integer scoreImpact) {
        this.indicatorCode = indicatorCode;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.scoreImpact = scoreImpact;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Scan getScan() { return scan; }
    public void setScan(Scan scan) { this.scan = scan; }

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
