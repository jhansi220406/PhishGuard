package com.phishguard.dto;

import java.util.List;

public class QuizSubmitRequest {
    private Long quizId = 1L;
    private List<AnswerEntry> answers;

    public static class AnswerEntry {
        private Long questionId;
        private int chosenIndex;

        public AnswerEntry() {}
        public AnswerEntry(Long questionId, int chosenIndex) {
            this.questionId = questionId;
            this.chosenIndex = chosenIndex;
        }

        public Long getQuestionId() { return questionId; }
        public void setQuestionId(Long questionId) { this.questionId = questionId; }

        public int getChosenIndex() { return chosenIndex; }
        public void setChosenIndex(int chosenIndex) { this.chosenIndex = chosenIndex; }
    }

    public QuizSubmitRequest() {}

    public Long getQuizId() { return quizId; }
    public void setQuizId(Long quizId) { this.quizId = quizId; }

    public List<AnswerEntry> getAnswers() { return answers; }
    public void setAnswers(List<AnswerEntry> answers) { this.answers = answers; }
}
