package com.phishguard.controller;

import com.phishguard.dto.ArticleDto;
import com.phishguard.dto.QuizQuestionDto;
import com.phishguard.dto.QuizResultDto;
import com.phishguard.dto.QuizSubmitRequest;
import com.phishguard.entity.User;
import com.phishguard.security.UserPrincipal;
import com.phishguard.service.AuthService;
import com.phishguard.service.AwarenessService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/awareness")
@Tag(name = "Security Awareness", description = "Cybersecurity educational articles and interactive quizzes")
public class AwarenessController {

    private final AwarenessService awarenessService;
    private final AuthService authService;

    public AwarenessController(AwarenessService awarenessService, AuthService authService) {
        this.awarenessService = awarenessService;
        this.authService = authService;
    }

    @GetMapping("/articles")
    @Operation(summary = "Get cybersecurity education articles")
    public ResponseEntity<List<ArticleDto>> getArticles() {
        return ResponseEntity.ok(awarenessService.getArticles());
    }

    @GetMapping("/quizzes")
    @Operation(summary = "Get interactive phishing detection scenario questions")
    public ResponseEntity<List<QuizQuestionDto>> getQuizzes() {
        return ResponseEntity.ok(awarenessService.getQuizQuestions());
    }

    @PostMapping("/quiz-results")
    @Operation(summary = "Submit quiz responses and calculate score with explanations")
    public ResponseEntity<QuizResultDto> submitQuiz(
            @RequestBody QuizSubmitRequest request,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        QuizResultDto result = awarenessService.evaluateQuiz(request, user);
        return ResponseEntity.ok(result);
    }
}
