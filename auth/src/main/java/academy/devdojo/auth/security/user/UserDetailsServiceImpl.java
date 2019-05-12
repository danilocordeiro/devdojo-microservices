package academy.devdojo.auth.security.user;

import academy.devdojo.core.model.ApplicationUser;
import academy.devdojo.core.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.Collection;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("Searching in the DB for user by username '{}'", username);

        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);

        if (applicationUser == null)
            throw new UsernameNotFoundException(String.format("Application user '%s' not found", username));

        log.info("Application user found '{}'", username);

        return new CustomUserDetails(applicationUser);
    }

    private static final class CustomUserDetails extends ApplicationUser implements UserDetails {

        CustomUserDetails(@NotNull ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList( "ROLE_" + this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
