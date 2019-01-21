package cn.jsbintask.securityrestful.repository;

import cn.jsbintask.securityrestful.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/11 11:37
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
}
