package com.phishguard.dto;

import java.util.List;

public class QuizQuestionDto {
    private Long id;
    private String scenario;
    private String question;
    private List<String> options;
    private int correctIndex;
    private String explanation;

    public QuizQuestionDto() {}
    public QuizQuestionDto(Long id, String scenario, String question, List<String> options, int correctIndex, String explanation) {
        this.id = id;
        this.scenario = scenario;
        this.question = question;
        this.options = options;
        this.correctIndex = correctIndex;
        this.explanation = explanation;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getScenario() { return scenario; }
    public void setScenario(String scenario) { this.scenario = scenario; }

    public String getQuestion() { return question; }
    public void setQuestion(String question) { this.question = question; }

    public List<String> getOptions() { return options; }
    public void setOptions(List<String> options) { this.options = options; }

    public int getCorrectIndex() { return correctIndex; }
    public void setCorrectIndex(int correctIndex) { this.correctIndex = correctIndex; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }
}
