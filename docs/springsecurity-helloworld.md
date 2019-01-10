---
title: springsecurity系列教程-helloworld
date: 2019-01-08 11:11
updated: 2019-01-08 11:11
tag: 
  - java
  - springsecurity
  - springboot
sourceId: springsecurity-helloworld
---

# SpringSecurity从Hello World到源码解析（一）：hello world程序入门
<img src="http://pkdfqapwh.bkt.clouddn.com/security.jpg">
<!-- more -->
> 摘要：权限控制在我们的项目当中一般都有用到，有简单的登录就搞定的权限访问，也有分级身份的权限控制，
而权限控制的方式对于不同的需求也有多种选择，小到使用代码硬编码，自定义过滤器，自定义拦截器等等。更加灵活的方式则是使用已有的权限工具。
如shiro，springsecurity等。而本系列博客将重点介绍springsecurity的工作原理以及应用。

> springsecurity的官方介绍：Spring Security是一个功能强大且可高度自定义的身份验证和访问控制框架。它是保护基于Spring的应用程序的框架。
Spring Security是一个专注于为Java应用程序提供身份验证和授权的框架。与所有Spring项目一样，Spring Security的真正强大之处在于它可以轻松扩展以满足自定义要求

**从上面的介绍我们知道，spring security是基于spring框架的，所以与spring基本无缝集成，而本系列博客也将使用最新的springboot（没接触过的可以先学习[springboot系列教程](https://jsbintask.cn/tags/springboot)）
进行演示，好了，说了这么多废话，接下来看hello world的入门搭建。**

## 环境搭建
基础环境，springboot: 2.1.1.RELEASE
注意，因为本项目演示有多个，所以我把他们构建成了多个子项目。
父pom文件：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <packaging>pom</packaging>
    <modules>
        <module>basic-security</module>
    </modules>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.1.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>cn.jsbintask</groupId>
    <artifactId>spring-security-demos</artifactId>
    <version>1.0.0</version>

    <name>spring-security-demos</name>
    <description>Demos project for Spring Security</description>

    <properties>
        <java.version>1.8</java.version>
    </properties>
</project>
```

hello-world版本pom文件：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <groupId>cn.jsbintask</groupId>
        <artifactId>spring-security-demos</artifactId>
        <version>1.0.0</version>
    </parent>

    <modelVersion>4.0.0</modelVersion>
    <artifactId>basic-security</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-freemarker</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```
注意上方引入了lombok和freemarker，主要为了演示方便。

## 基础配置
1. 环境搭建好后，接下来开始编写helloworld程序，首先编写一个freemarker模板（不知道的可以当作html处理）
**hello.html放到templates目录下方**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>hello</title>
</head>
<body>
    <h2>hello world from jsbintask.</h2>
</body>
</html>
```

2. 修改application.yml
```yaml
server:
  port: 8080

spring:
  freemarker:
    enabled: true
    cache: false
    template-loader-path: classpath:/templates/
    suffix: .html

  security:
    user:
      name: user
      password: admin
      roles: user, admin
```
上方配置先不进行讲解，下章解析工作原理时会着重进行讲解，各位可以先跟着配置。

3. 编写controller
```java
@Controller
@RequestMapping
public class HelloController {

    @RequestMapping("/hello")
    public String hello(ModelAndView mv) {
        return "hello";
    }
}
```
此处为映射请求 /hello 到我们编写的 hello.html程序。

4. 启动应用（main app)
接下来我们在浏览器访问 [hello](http://localhost:8080/hello), 出现如下拦截页面：
<img src="https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo1.png" />
代表我们的hello请求已经被拦截。接下来输入 application.yml中配置的用户名密码，成功访问。
![springsecurity](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo2.png)
**我们的helloworld程序也就成功了。**

## 总结
本hello world程序展示了springboot结合springsecurity基础配置，接下来我将讲解springsecurity是如何工作的。
本项目git地址：[spring-security-demos](https://github.com/jsbintask22/spring-security-demos)