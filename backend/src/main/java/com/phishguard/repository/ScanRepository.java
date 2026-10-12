package com.phishguard.repository;

import com.phishguard.entity.Scan;
import com.phishguard.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

    // Record ownership queries
    Optional<Scan> findByIdAndUser(Long id, User user);

    Page<Scan> findByUser(User user, Pageable pageable);

    @Query("SELECT s FROM Scan s WHERE s.user = :user " +
           "AND (:scanType IS NULL OR s.scanType = :scanType) " +
           "AND (:riskLevel IS NULL OR s.riskLevel = :riskLevel) " +
           "AND (:search IS NULL OR LOWER(s.submittedContent) LIKE LOWER(CONCAT('%', :search, '%')) OR LOWER(s.destinationHostname) LIKE LOWER(CONCAT('%', :search, '%')))")
    Page<Scan> findFiltered(
        @Param("user") User user,
        @Param("scanType") String scanType,
        @Param("riskLevel") String riskLevel,
        @Param("search") String search,
        Pageable pageable
    );

    @Query("SELECT s FROM Scan s WHERE " +
           "(:scanType IS NULL OR s.scanType = :scanType) " +
           "AND (:riskLevel IS NULL OR s.riskLevel = :riskLevel) " +
           "AND (:search IS NULL OR LOWER(s.submittedContent) LIKE LOWER(CONCAT('%', :search, '%')) OR LOWER(s.destinationHostname) LIKE LOWER(CONCAT('%', :search, '%')))")
    Page<Scan> findFilteredAll(
        @Param("scanType") String scanType,
        @Param("riskLevel") String riskLevel,
        @Param("search") String search,
        Pageable pageable
    );

    List<Scan> findTop10ByUserOrderByScannedAtDesc(User user);

    List<Scan> findTop10ByOrderByScannedAtDesc();

    long countByUser(User user);
    long countByUserAndScanType(User user, String scanType);
    long countByUserAndRiskLevel(User user, String riskLevel);
    long countByUserAndRiskLevelIn(User user, List<String> riskLevels);

    long countByScanType(String scanType);
    long countByRiskLevel(String riskLevel);
    long countByRiskLevelIn(List<String> riskLevels);

    @Query("SELECT s FROM Scan s WHERE s.scannedAt >= :since ORDER BY s.scannedAt ASC")
    List<Scan> findRecentSince(@Param("since") LocalDateTime since);

    @Query("SELECT s FROM Scan s WHERE s.user = :user AND s.scannedAt >= :since ORDER BY s.scannedAt ASC")
    List<Scan> findRecentByUserSince(@Param("user") User user, @Param("since") LocalDateTime since);
}
