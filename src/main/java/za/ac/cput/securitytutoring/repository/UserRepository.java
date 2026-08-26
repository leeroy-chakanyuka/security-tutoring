package za.ac.cput.securitytutoring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import za.ac.cput.securitytutoring.model.User;


// basics but remember <myModel, typeOfId>
public interface UserRepository extends JpaRepository<User, Long> {
}
