package com.phishguard.controller;

import com.phishguard.dto.QrScanRequest;
import com.phishguard.dto.ScanResponse;
import com.phishguard.dto.UrlScanRequest;
import com.phishguard.entity.User;
import com.phishguard.security.UserPrincipal;
import com.phishguard.service.AuthService;
import com.phishguard.service.ScanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/scans")
@Tag(name = "Threat Scans", description = "URL heuristic inspection and QR code threat analysis")
public class ScanController {

    private final ScanService scanService;
    private final AuthService authService;

    public ScanController(ScanService scanService, AuthService authService) {
        this.scanService = scanService;
        this.authService = authService;
    }

    @PostMapping("/url")
    @Operation(summary = "Inspect a URL for heuristic phishing indicators")
    public ResponseEntity<ScanResponse> analyzeUrl(
            @Valid @RequestBody UrlScanRequest request,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        ScanResponse response = scanService.analyzeAndSaveUrl(request.getUrl(), user);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr")
    @Operation(summary = "Analyze a decoded QR code payload")
    public ResponseEntity<ScanResponse> analyzeQr(
            @Valid @RequestBody QrScanRequest request,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        ScanResponse response = scanService.analyzeAndSaveQr(request.getContent(), request.getScanType(), user);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    @Operation(summary = "List personal scan history with filters and pagination")
    public ResponseEntity<Page<ScanResponse>> getHistory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String scanType,
            @RequestParam(required = false) String riskLevel,
            @RequestParam(required = false) String search,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        Page<ScanResponse> scans = scanService.getUserScans(user, page, size, scanType, riskLevel, search);
        return ResponseEntity.ok(scans);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get full details of a specific scan record")
    public ResponseEntity<ScanResponse> getScanById(
            @PathVariable Long id,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        ScanResponse scan = scanService.getScanById(id, user);
        return ResponseEntity.ok(scan);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an owned scan record")
    public ResponseEntity<Map<String, String>> deleteScan(
            @PathVariable Long id,
            @AuthenticationPrincipal UserPrincipal principal
    ) {
        User user = (principal != null) ? authService.getCurrentUserEntity(principal) : null;
        scanService.deleteScanById(id, user);
        return ResponseEntity.ok(Map.of("message", "Scan record deleted successfully."));
    }
}
