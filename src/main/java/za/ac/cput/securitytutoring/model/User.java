package za.ac.cput.securitytutoring.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // fills in the getters and setters for us
@Builder // lets us build our object field for field
@NoArgsConstructor // needed for jpa
@AllArgsConstructor
@Entity
public class User {
    @Id
    @GeneratedValue // let it use the default - uses the TABLE enum for MYSQL
    private Long id;
    private String firstName;
    private String lastName;
    private String userame;
    private String password;

}
