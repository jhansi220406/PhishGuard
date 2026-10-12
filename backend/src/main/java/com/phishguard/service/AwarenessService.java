package com.phishguard.service;

import com.phishguard.dto.*;
import com.phishguard.entity.QuizResult;
import com.phishguard.entity.User;
import com.phishguard.repository.QuizResultRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class AwarenessService {

    private final QuizResultRepository quizResultRepository;

    public AwarenessService(QuizResultRepository quizResultRepository) {
        this.quizResultRepository = quizResultRepository;
    }

    public List<ArticleDto> getArticles() {
        return List.of(
                new ArticleDto(
                        1L,
                        "QRishing: The Dark Side of Quick Response Codes",
                        "NEW THREAT VECTOR",
                        "4 min read",
                        "How attackers use physical QR code stickers to bypass endpoint email scanners and trick mobile users into visiting credential harvester portals.",
                        "Quishing exploits the visual illegibility of 2D barcodes. Attackers target parking meters, restaurant ordering points, and transit ticketing hubs with malicious sticker overlays.",
                        "Never scan unverified public stickers. Review the decoded destination hostname on PhishGuard before interacting."
                ),
                new ArticleDto(
                        2L,
                        "The HTTPS Fallacy: The Green Padlock is Not a Shield",
                        "COMMON MISCONCEPTION",
                        "3 min read",
                        "Why having an active SSL/TLS certificate does NOT prove that a website is legitimate or safe from fraud.",
                        "HTTPS encrypts the communication channel between client and server, preventing local Wi-Fi sniffing. Over 80% of phishing kits obtain automated free TLS certificates.",
                        "Verify the registered domain identity against official bookmarks, not just the presence of a padlock icon."
                ),
                new ArticleDto(
                        3L,
                        "Typosquatting & Unicode Homoglyph Impersonation",
                        "DECEPTION TACTIC",
                        "5 min read",
                        "Understanding how Cyrillic homoglyphs and typosquatting mimic trusted bank and technology brands.",
                        "Attackers exploit Internationalized Domain Names (IDN) by substituting Latin characters with visually identical Cyrillic glyphs (e.g. Cyrillic 'а').",
                        "Use modern password managers that enforce strict origin matching, preventing credential entry on lookalike domains."
                ),
                new ArticleDto(
                        4L,
                        "Artificial Urgency: The Psychological Trap",
                        "SOCIAL ENGINEERING",
                        "3 min read",
                        "How panic and urgency impair critical decision-making in phishing attacks.",
                        "Phishing lures manipulate adrenaline and anxiety through simulated crises like account suspension or unauthorized wire transfers.",
                        "Always pause when encountering urgent messages. Contact organizations via official out-of-band channels."
                )
        );
    }

    public List<QuizQuestionDto> getQuizQuestions() {
        return List.of(
                new QuizQuestionDto(
                        1L,
                        "You receive an SMS alert saying: 'Your bank card is restricted. Re-authenticate immediately at http://192.168.1.55/chase-auth to prevent account closure.'",
                        "Which red flag is the most critical technical indicator that this message is fraudulent?",
                        List.of(
                                "The message was sent via SMS instead of email.",
                                "The destination URL uses a raw IP address instead of the official bank domain.",
                                "The message has urgent wording.",
                                "The link lacks a query parameter."
                        ),
                        1,
                        "Legitimate financial institutions NEVER host login portals on raw, unmapped IP addresses (like 192.168.x.x). IP hostnames bypass standard DNS records and are characteristic of short-lived attacker infrastructure."
                ),
                new QuizQuestionDto(
                        2L,
                        "A QR code sticker is placed on a city parking meter. When scanned, your phone reveals the destination: 'https://pay-parking-city.com.checkout-sys.tk/pay'",
                        "Why should you NOT proceed to enter your credit card on this destination?",
                        List.of(
                                "It is impossible for parking meters to use QR codes.",
                                "The website uses HTTPS, which proves it is safe.",
                                "The actual registered hostname is 'checkout-sys.tk', with a high-risk TLD (.tk) and deceptive subdomains.",
                                "The QR code took more than 2 seconds to scan."
                        ),
                        2,
                        "In a URL, the true host is the part directly before the final domain suffix. 'checkout-sys.tk' is the real domain, whereas 'pay-parking-city.com' is merely a deceptive subdomain designed to trick visual inspection."
                ),
                new QuizQuestionDto(
                        3L,
                        "You receive an email from 'IT Support' asking you to update your campus password at 'https://login.unıversity.edu/portal' (notice the dotless 'ı' in university).",
                        "What specific attack vector is being employed here?",
                        List.of(
                                "DDoS attack",
                                "Homoglyph / Punycode lookalike domain impersonation",
                                "SQL Injection",
                                "Cross-Site Scripting (XSS)"
                        ),
                        1,
                        "This is an IDN Homoglyph attack. Attackers substitute Latin 'i' with Turkish dotless 'ı'. When resolved by DNS, it targets an entirely different server while looking virtually identical to the naked eye."
                ),
                new QuizQuestionDto(
                        4L,
                        "An email contains a link formatted as 'https://paypal.com@login-verification-trap.com/security'.",
                        "Where will your browser actually navigate if you click this link?",
                        List.of(
                                "To paypal.com",
                                "To login-verification-trap.com",
                                "The browser will refuse to open any link with an @ symbol",
                                "To a split-screen session"
                        ),
                        1,
                        "In URL standard RFC 3986, characters before the '@' symbol are treated as basic HTTP user-info credentials. The browser connects strictly to 'login-verification-trap.com'."
                )
        );
    }

    @Transactional
    public QuizResultDto evaluateQuiz(QuizSubmitRequest request, User user) {
        List<QuizQuestionDto> questions = getQuizQuestions();
        int score = 0;
        int total = questions.size();
        List<QuizResultDto.QuestionFeedback> feedbackList = new ArrayList<>();

        for (QuizQuestionDto q : questions) {
            int chosen = -1;
            if (request.getAnswers() != null) {
                for (QuizSubmitRequest.AnswerEntry entry : request.getAnswers()) {
                    if (entry.getQuestionId().equals(q.getId())) {
                        chosen = entry.getChosenIndex();
                        break;
                    }
                }
            }

            boolean isCorrect = (chosen == q.getCorrectIndex());
            if (isCorrect) score++;

            feedbackList.add(new QuizResultDto.QuestionFeedback(
                    q.getId(),
                    isCorrect,
                    q.getCorrectIndex(),
                    q.getExplanation()
            ));
        }

        int percentage = Math.round(((float) score / total) * 100);
        String level = percentage >= 80 ? "EXPERT" : (percentage >= 50 ? "INTERMEDIATE" : "NOVICE");

        QuizResult entity = new QuizResult(user, request.getQuizId(), score, total);
        quizResultRepository.save(entity);

        QuizResultDto resultDto = new QuizResultDto();
        resultDto.setScore(score);
        resultDto.setTotalQuestions(total);
        resultDto.setPercentage(percentage);
        resultDto.setFeedbackLevel(level);
        resultDto.setFeedback(feedbackList);

        return resultDto;
    }
}
