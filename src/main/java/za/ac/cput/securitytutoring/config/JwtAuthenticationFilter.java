package za.ac.cput.securitytutoring.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import za.ac.cput.securitytutoring.service.JwtService;

import java.io.IOException;

/**
 * every incoming request MUST PASS through this filter to check for a JWT.
 * <p>
 * Registered as a {@code @Component} so it gets loaded into the Spring container.
 */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * It's important to keep a mental model of the data we receive at this point
     * in the method. It looks something like this:
     * <pre>{@code
     * {
     *   "method": "GET",
     *   "url": "/api/users/me",
     *   "headers": {
     *     "Host": "localhost:8080",
     *     "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *     "Content-Type": "application/json",
     *     "Accept": "application/json"
     *   },
     *   "body": null
     * }
     * }</pre>
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        final String jwt;
        final String userEmail;
        /* simply just grab the right field from the json */
        final String authHeader = request.getHeader("Authorization");

        /* against intuition, here we have to let the request through whether or not it
         *  has the appropriate token, if not, not our job rn the rest we see ahead
         */
        if(authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);
            return;
        }

        /* Bearer is six words + the space = 8, minus one since counting in programming
         *  starts at 0, our token starts at index number seven
         */
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUser(jwt);

        /* now we check that the current user is NOT authenticated, if they are, just send em through*/
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            /* email is valid (properly extracted from the jwt) but they are not authenticated, grab email from db */
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if(jwtService.isTokenValid(jwt, userDetails )){
                /* our (jwt) token is valid, now we need to create an object that tells spring
                 * who this is and what perms they have */
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, /*who*/
                        null, /*password*/
                        userDetails.getAuthorities() /*perms or roles */
                        );

                /* we add to the token above, details about the request, like IP etc */
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                /* the user is now authenticated, look at the check in the first / parent if */
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        /*pass it onto next filter step */
        filterChain.doFilter(request, response);

        
    }
}
