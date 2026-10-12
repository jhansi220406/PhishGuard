package com.phishguard.repository;

import com.phishguard.entity.QuizResult;
import com.phishguard.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface QuizResultRepository extends JpaRepository<QuizResult, Long> {
    List<QuizResult> findByUserOrderByCompletedAtDesc(User user);
    long countByUser(User user);
}
