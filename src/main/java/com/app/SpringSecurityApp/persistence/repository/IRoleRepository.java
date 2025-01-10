package com.app.SpringSecurityApp.persistence.repository;

import com.app.SpringSecurityApp.persistence.entity.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IRoleRepository extends CrudRepository<RoleEntity, Long> {

    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames);

}
