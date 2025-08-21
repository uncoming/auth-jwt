package com.security.authjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.security.authjwt.entity.User;

@Repository
public interface IUserRepository extends JpaRepository<User, Long> {

    Optional<User> getByUsername(String username);

}
