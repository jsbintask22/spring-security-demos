package cn.jsbintask.securityrestful.util;

import cn.jsbintask.securityrestful.domain.AuthUser;
import cn.jsbintask.securityrestful.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 11:03
 */
public class JwtUtil {
    private static final String secret = "jsbintask@gmail.com";

    public static String generateToken(String username, List<Role> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles.parallelStream().map(Role::getRoleName).collect(Collectors.joining(",")));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                //创建时间
                .setIssuedAt(new Date())
                //过期时间，我们设置为 五分钟
                .setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
                //签名，通过密钥保证安全性
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public static AuthUser parseToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        String username = claims.getSubject();
        String roles = (String) claims.get("roles");

        //因为生成的时候没有放入密码，所以不需要密码
        return new AuthUser(username, null, Arrays.stream(roles.split(",")).map(name -> {
            Role role = new Role();
            role.setRoleName(name);
            return role;
        }).collect(Collectors.toList()));
    }
}
