package cn.jsbintask.basicsecurity.service;

import cn.jsbintask.basicsecurity.domain.AuthUser;
import cn.jsbintask.basicsecurity.domain.User;
import cn.jsbintask.basicsecurity.repository.RoleRepository;
import cn.jsbintask.basicsecurity.repository.UserRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/10 14:53
 */
@Service
@Primary
public class CustomUserDetailsServiceImpl implements UserDetailsService {
    @Resource
    private UserRepository userRepository;

    @Resource
    private RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("user: " + username + " is not found.");
        }

        return new AuthUser(user.getUsername(), user.getPassword(), roleRepository.findAllById(Collections.singletonList(user.getRoleId())));
    }
}
