package com.backend.jwtauthentication.repository;

import com.backend.jwtauthentication.entity.ERole;
import com.backend.jwtauthentication.entity.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role,String> {
  Optional<Role> findByName(ERole name);

}
