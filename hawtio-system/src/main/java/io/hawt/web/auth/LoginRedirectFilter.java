package io.hawt.web.auth;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Redirect to login page when authentication is enabled.
 */
public class LoginRedirectFilter implements Filter {

    private AuthenticationConfiguration authConfiguration;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        authConfiguration = AuthenticationConfiguration.getConfiguration(filterConfig.getServletContext());
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(false);

        if (authConfiguration.isEnabled() && !authConfiguration.isKeycloakEnabled()
            && !isAuthenticated(session)) {
            redirect(httpRequest, httpResponse);
        } else {
            chain.doFilter(request, response);
        }
    }

    private boolean isAuthenticated(HttpSession session) {
        return session != null && session.getAttribute("subject") != null;
    }

    private void redirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
        httpResponse.sendRedirect(httpRequest.getContextPath() + AuthenticationConfiguration.LOGIN_URL);
    }

    @Override
    public void destroy() {
    }
}
