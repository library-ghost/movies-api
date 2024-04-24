package dev.libraryghost.movies.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import dev.libraryghost.movies.models.ERole;
import dev.libraryghost.movies.models.Role;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
  }
