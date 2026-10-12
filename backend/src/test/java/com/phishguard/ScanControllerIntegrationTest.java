package com.phishguard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.dto.AuthRequest;
import com.phishguard.dto.RegisterRequest;
import com.phishguard.dto.UrlScanRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/scans/url should analyze a valid URL and return explainable risk response")
    void testAnalyzeUrlEndpoint() throws Exception {
        UrlScanRequest request = new UrlScanRequest("https://safe-demo-university.edu/research");

        mockMvc.perform(post("/api/scans/url")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanType").value("URL"))
                .andExpect(jsonPath("$.riskLevel").value("LOW"))
                .andExpect(jsonPath("$.riskScore", lessThan(30)))
                .andExpect(jsonPath("$.destinationHostname").value("safe-demo-university.edu"))
                .andExpect(jsonPath("$.recommendations", notNullValue()));
    }

    @Test
    @DisplayName("POST /api/scans/url with blank URL should return 400 validation error")
    void testAnalyzeUrlValidationError() throws Exception {
        UrlScanRequest request = new UrlScanRequest("");

        mockMvc.perform(post("/api/scans/url")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    @DisplayName("POST /api/auth/register should create user and return JWT bearer token")
    void testUserRegistration() throws Exception {
        String uniqueEmail = "testuser_" + System.currentTimeMillis() + "@security.edu";
        RegisterRequest request = new RegisterRequest("Test Analyst", uniqueEmail, "SecurePassword123!");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value(uniqueEmail));
    }

    @Test
    @DisplayName("POST /api/auth/login should authenticate seeded demo analyst")
    void testDemoAnalystLogin() throws Exception {
        AuthRequest request = new AuthRequest("analyst@phishguard.security", "PhishGuard@2026");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.user.email").value("analyst@phishguard.security"));
    }

    @Test
    @DisplayName("POST /api/auth/login with invalid password should return 401 Unauthorized")
    void testBadCredentials() throws Exception {
        AuthRequest request = new AuthRequest("analyst@phishguard.security", "WrongPassword999");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/dashboard/summary should return high-level security metrics")
    void testDashboardSummary() throws Exception {
        mockMvc.perform(get("/api/dashboard/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalScans", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.urlScans", greaterThanOrEqualTo(0)));
    }

    @Test
    @DisplayName("GET /api/awareness/quizzes should return security scenario questions")
    void testAwarenessQuizzes() throws Exception {
        mockMvc.perform(get("/api/awareness/quizzes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThan(0))))
                .andExpect(jsonPath("$[0].question", notNullValue()));
    }
}
