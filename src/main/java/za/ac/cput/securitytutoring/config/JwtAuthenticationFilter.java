package za.ac.cput.securitytutoring.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * the class we are implementing helps make sure that every request we get runs through this filter
 * we have to load it into the container so @Component
 *
 */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {


        /*
         * It is important to keep a mental model of the data we receive in this method at this point
         * it would look something like this:
             1  {
                  "method": "GET",
                  "url": "/api/users/me",
                  "headers": {
                    "Host": "localhost:8080",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                  },
                  "body": null
                }
         */

        /* simply just grab the right field from the json */
        String authHeader = request.getHeader("Authorization");

        String jwt;

        /* against intuition, here we have to let the request through whether or not it
        *  has the appropriate token, if not, not our job rn the rest we see ahead */
        if(authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);
        }

        /* Bearer is six words + the space = 8, minus one since counting in programming
        *  starts at 0, our token starts at index number seven*/
        jwt = authHeader.substring(7);
    }
}
