package com.phishguard.controller;

import com.phishguard.dto.DashboardActivityDto;
import com.phishguard.dto.DashboardSummaryDto;
import com.phishguard.entity.User;
import com.phishguard.security.UserPrincipal;
import com.phishguard.service.AuthService;
import com.phishguard.service.DashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
@Tag(name = "Dashboard", description = "Aggregated security metrics, charts, and activity logs")
public class DashboardController {

    private final DashboardService dashboardService;
    private final AuthService authService;

    public DashboardController(DashboardService dashboardService, AuthService authService) {
        this.dashboardService = dashboardService;
        this.authService = authService;
    }

    @GetMapping("/summary")
    @Operation(summary = "Get high-level summary statistics cards")
    public ResponseEntity<DashboardSummaryDto> getSummary(@AuthenticationPrincipal UserPrincipal principal) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        DashboardSummaryDto summary = dashboardService.getSummary(user);
        return ResponseEntity.ok(summary);
    }

    @GetMapping("/activity")
    @Operation(summary = "Get chart timelines, risk distribution, and top indicators")
    public ResponseEntity<DashboardActivityDto> getActivity(@AuthenticationPrincipal UserPrincipal principal) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        DashboardActivityDto activity = dashboardService.getActivity(user);
        return ResponseEntity.ok(activity);
    }
}
