package hello.security.model;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user")
@Data
public class User {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    @Enumerated(EnumType.STRING)
    private Role role;

    // oauth2 에서 받은 정보를 가지고 만들예정
    // oauth2를 발급해주는 곳
    private String provider;
    // {sub}
    private String providerId;
    @CreationTimestamp
    private LocalDateTime createDate;
}
