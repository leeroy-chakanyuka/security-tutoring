package za.ac.cput.securitytutoring.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data // fills in the getters and setters for us
@Builder // lets us build our object field for field
@NoArgsConstructor // needed for jpa
@AllArgsConstructor
@Entity
public class User implements UserDetails {
    @Id
    @GeneratedValue // let it use the default - uses the TABLE enum for MYSQL
    private Long id;
    private String firstName;
    private String lastName;
    private String userame;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;


    /**
     * by overriding this and returning a SimpleGrantedAuthority (where we may have a list of roles - roles
     * have permissions associated with them - we tell spring "hey this user is this type, let them only do the things
     * their role has permissions for")
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

}
