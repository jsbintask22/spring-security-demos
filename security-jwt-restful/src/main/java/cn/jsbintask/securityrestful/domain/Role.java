package cn.jsbintask.securityrestful.domain;

import lombok.Data;

import javax.persistence.*;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/11 11:35
 */
@Entity
@Table
@Data
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String roleName;
    private String description;
}
