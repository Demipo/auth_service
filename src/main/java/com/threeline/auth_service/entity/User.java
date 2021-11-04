package com.threeline.auth_service.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;

@Entity
@Inheritance(strategy = InheritanceType.JOINED)
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class User extends AuditModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Username should not be blank")
    @Column(nullable = false, unique = true)
    private String userName;
    
    @NotBlank(message = "Last name should not be blank")
    private String lastName;
    
    @NotBlank(message = "First name should not be blank")
    private String firstName;
    
    @Email(message = "Email has to be a valid email address")
    @NotBlank(message = "Email should not be blank")
    @Column(nullable = false, unique = true)
    private String email;

    @NotBlank(message = "Phone number should not be blank")
    @Column(nullable = false, unique = true)
    private String phone;

    @NotBlank(message = "Status should not be blank")
    private String status;

    @NotBlank(message = "Password should not be blank")
    @JsonIgnoreProperties
    private String password;

    @NotBlank(message = "Address should not be blank")
    private String contactAddress;

    @NotBlank(message = "UserId should not be blank")
    private String userId;

    @NotBlank(message = "UserId should not be blank")
    private String userType;



     /*@ManyToMany(fetch = FetchType.EAGER)
     @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "role_id"), inverseJoinColumns = @JoinColumn(name = "user_id"))
     private List<Role> roles = new ArrayList<>();*/
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        return id != null && id.equals(((User) o).getId());
    }
 
    @Override
    public int hashCode() {
        return 31;
    }

}