package za.ac.cput.securitytutoring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import za.ac.cput.securitytutoring.model.User;

import java.util.Optional;


// basics but remember <myModel, typeOfId>
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUser(String username);
}
