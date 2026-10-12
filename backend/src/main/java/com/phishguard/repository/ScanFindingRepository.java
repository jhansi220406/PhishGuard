package com.phishguard.repository;

import com.phishguard.entity.ScanFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanFindingRepository extends JpaRepository<ScanFinding, Long> {

    @Query("SELECT f.indicatorCode, COUNT(f) FROM ScanFinding f GROUP BY f.indicatorCode ORDER BY COUNT(f) DESC")
    List<Object[]> findTopIndicatorCounts();
}
