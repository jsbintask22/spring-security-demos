package cn.jsbintask.securityrestful.domain;

import lombok.Data;

import javax.persistence.*;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/11 11:34
 */
@Table
@Entity
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String username;
    private String password;

    private Integer age;

    private String address;

    private Integer roleId;
}
