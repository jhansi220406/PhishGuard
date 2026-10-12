package com.phishguard.service;

import com.phishguard.dto.ScanFindingDto;
import com.phishguard.dto.ScanResponse;
import com.phishguard.entity.Scan;
import com.phishguard.entity.ScanFinding;
import com.phishguard.entity.User;
import com.phishguard.repository.ScanRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ScanService {

    private final ScanRepository scanRepository;
    private final UrlAnalysisService urlAnalysisService;
    private final QrProcessingService qrProcessingService;

    public ScanService(ScanRepository scanRepository,
                       UrlAnalysisService urlAnalysisService,
                       QrProcessingService qrProcessingService) {
        this.scanRepository = scanRepository;
        this.urlAnalysisService = urlAnalysisService;
        this.qrProcessingService = qrProcessingService;
    }

    @Transactional
    public ScanResponse analyzeAndSaveUrl(String rawUrl, User currentUser) {
        ScanResponse response = urlAnalysisService.analyzeUrl(rawUrl);
        return persistScan(response, currentUser);
    }

    @Transactional
    public ScanResponse analyzeAndSaveQr(String rawContent, String scanType, User currentUser) {
        ScanResponse response = qrProcessingService.processQrPayload(rawContent);
        if (scanType != null && !scanType.isBlank()) {
            response.setScanType(scanType);
        }
        return persistScan(response, currentUser);
    }

    private ScanResponse persistScan(ScanResponse response, User user) {
        Scan scan = new Scan();
        scan.setUser(user);
        scan.setScanType(response.getScanType());
        scan.setSubmittedContent(response.getSubmittedContent());
        scan.setDestinationHostname(response.getDestinationHostname());
        scan.setDetectedContentType(response.getDetectedContentType());
        scan.setRiskLevel(response.getRiskLevel());
        scan.setRiskScore(response.getRiskScore());
        scan.setThreatProviderStatus(response.getThreatProviderStatus());
        scan.setScannedAt(response.getScannedAt());

        if (response.getFindings() != null) {
            for (ScanFindingDto fDto : response.getFindings()) {
                ScanFinding finding = new ScanFinding(
                        fDto.getIndicatorCode(),
                        fDto.getTitle(),
                        fDto.getDescription(),
                        fDto.getSeverity(),
                        fDto.getScoreImpact()
                );
                scan.addFinding(finding);
            }
        }

        Scan saved = scanRepository.save(scan);
        response.setId(saved.getId());
        return response;
    }

    @Transactional(readOnly = true)
    public Page<ScanResponse> getUserScans(User user, int page, int size, String scanType, String riskLevel, String search) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "scannedAt"));
        String cleanType = (scanType != null && !scanType.isBlank()) ? scanType.trim().toUpperCase() : null;
        String cleanRisk = (riskLevel != null && !riskLevel.isBlank()) ? riskLevel.trim().toUpperCase() : null;
        String cleanSearch = (search != null && !search.isBlank()) ? search.trim() : null;

        Page<Scan> scansPage;
        if (user != null) {
            scansPage = scanRepository.findFiltered(user, cleanType, cleanRisk, cleanSearch, pageable);
        } else {
            scansPage = scanRepository.findFilteredAll(cleanType, cleanRisk, cleanSearch, pageable);
        }

        return scansPage.map(this::mapToResponse);
    }

    @Transactional(readOnly = true)
    public ScanResponse getScanById(Long id, User currentUser) {
        Scan scan = scanRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan record not found with ID: " + id));

        // Enforce ownership: user can only inspect their own scan (or anonymous scans)
        if (currentUser != null && scan.getUser() != null && !scan.getUser().getId().equals(currentUser.getId())) {
            throw new AccessDeniedException("You do not have permission to view this scan record.");
        }

        return mapToResponse(scan);
    }

    @Transactional
    public void deleteScanById(Long id, User currentUser) {
        Scan scan = scanRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan record not found with ID: " + id));

        // Enforce ownership: only the owner can delete
        if (currentUser != null) {
            if (scan.getUser() != null && !scan.getUser().getId().equals(currentUser.getId())) {
                throw new AccessDeniedException("You do not have permission to delete this scan record.");
            }
        }

        scanRepository.delete(scan);
    }

    public ScanResponse mapToResponse(Scan scan) {
        ScanResponse dto = new ScanResponse();
        dto.setId(scan.getId());
        dto.setScanType(scan.getScanType());
        dto.setSubmittedContent(scan.getSubmittedContent());
        dto.setDestinationHostname(scan.getDestinationHostname());
        dto.setDetectedContentType(scan.getDetectedContentType());
        dto.setRiskLevel(scan.getRiskLevel());
        dto.setRiskScore(scan.getRiskScore());
        dto.setThreatProviderStatus(scan.getThreatProviderStatus());
        dto.setScannedAt(scan.getScannedAt());

        if (scan.getFindings() != null) {
            List<ScanFindingDto> findingDtos = scan.getFindings().stream()
                    .map(f -> new ScanFindingDto(
                            f.getIndicatorCode(),
                            f.getTitle(),
                            f.getDescription(),
                            f.getSeverity(),
                            f.getScoreImpact()
                    ))
                    .collect(Collectors.toList());
            dto.setFindings(findingDtos);
        }

        // Reconstruct contextual recommendations
        if ("HIGH".equalsIgnoreCase(scan.getRiskLevel())) {
            dto.getRecommendations().add("Do NOT provide passwords or personal details on this destination.");
            dto.getRecommendations().add("Check whether the domain spelling accurately matches official bookmarks.");
        } else if ("MEDIUM".equalsIgnoreCase(scan.getRiskLevel())) {
            dto.getRecommendations().add("Exercise caution before proceeding.");
            dto.getRecommendations().add("Verify sender identity via independent out-of-band communication.");
        } else {
            dto.getRecommendations().add("Domain structure adheres to standard legitimate conventions.");
            dto.getRecommendations().add("Always ensure destination certificates match expected organizations.");
        }

        return dto;
    }
}
