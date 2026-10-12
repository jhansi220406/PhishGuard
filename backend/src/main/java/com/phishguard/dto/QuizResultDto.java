package com.phishguard.dto;

import java.util.ArrayList;
import java.util.List;

public class QuizResultDto {
    private int score;
    private int totalQuestions;
    private int percentage;
    private String feedbackLevel;
    private List<QuestionFeedback> feedback = new ArrayList<>();

    public static class QuestionFeedback {
        private Long questionId;
        private boolean correct;
        private int correctIndex;
        private String explanation;

        public QuestionFeedback() {}
        public QuestionFeedback(Long questionId, boolean correct, int correctIndex, String explanation) {
            this.questionId = questionId;
            this.correct = correct;
            this.correctIndex = correctIndex;
            this.explanation = explanation;
        }

        public Long getQuestionId() { return questionId; }
        public void setQuestionId(Long questionId) { this.questionId = questionId; }

        public boolean isCorrect() { return correct; }
        public void setCorrect(boolean correct) { this.correct = correct; }

        public int getCorrectIndex() { return correctIndex; }
        public void setCorrectIndex(int correctIndex) { this.correctIndex = correctIndex; }

        public String getExplanation() { return explanation; }
        public void setExplanation(String explanation) { this.explanation = explanation; }
    }

    public QuizResultDto() {}

    public int getScore() { return score; }
    public void setScore(int score) { this.score = score; }

    public int getTotalQuestions() { return totalQuestions; }
    public void setTotalQuestions(int totalQuestions) { this.totalQuestions = totalQuestions; }

    public int getPercentage() { return percentage; }
    public void setPercentage(int percentage) { this.percentage = percentage; }

    public String getFeedbackLevel() { return feedbackLevel; }
    public void setFeedbackLevel(String feedbackLevel) { this.feedbackLevel = feedbackLevel; }

    public List<QuestionFeedback> getFeedback() { return feedback; }
    public void setFeedback(List<QuestionFeedback> feedback) { this.feedback = feedback; }
}
