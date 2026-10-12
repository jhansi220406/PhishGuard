package com.phishguard.dto;

public class ArticleDto {
    private Long id;
    private String title;
    private String tag;
    private String readTime;
    private String summary;
    private String content;
    private String keyDefense;

    public ArticleDto() {}
    public ArticleDto(Long id, String title, String tag, String readTime, String summary, String content, String keyDefense) {
        this.id = id;
        this.title = title;
        this.tag = tag;
        this.readTime = readTime;
        this.summary = summary;
        this.content = content;
        this.keyDefense = keyDefense;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getTag() { return tag; }
    public void setTag(String tag) { this.tag = tag; }

    public String getReadTime() { return readTime; }
    public void setReadTime(String readTime) { this.readTime = readTime; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getKeyDefense() { return keyDefense; }
    public void setKeyDefense(String keyDefense) { this.keyDefense = keyDefense; }
}
