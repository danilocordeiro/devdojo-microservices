package academy.devdojo.core.repository;

import academy.devdojo.core.model.ApplicationUser;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

    public ApplicationUser findByUsername(String username);
}
