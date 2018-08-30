/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.geoserver.security.config.PreAuthenticatedUserNameFilterConfig;
import org.geoserver.security.config.SecurityAuthFilterConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * The GeoServer OAuth2 Filter Configuration. This POJO contains the properties needed to correctly
 * configure the Spring Auth Filter.
 *
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 */
public class OAuth2FilterConfig extends PreAuthenticatedUserNameFilterConfig
        implements SecurityAuthFilterConfig {

    /** serialVersionUID */
    private static final long serialVersionUID = -3551428051398501603L;

    // DEFAULT VALUES - BEGIN -
    protected String cliendId;

    protected String clientSecret;

    protected String accessTokenUri = "https://auth_domain/oauth/token/";

    protected String userAuthorizationUri = "https://auth_domain/oauth/authorize/";

    protected String redirectUri = "http://localhost:8080/geoserver";

    protected String checkTokenEndpointUrl = "https://auth_domain/check_token/";

    protected String logoutUri = "https://auth_domain/logout/";

    protected String scopes = "read,write,groups";

    protected Boolean enableRedirectAuthenticationEntryPoint = false;

    protected Boolean forceAccessTokenUriHttps = true;

    protected Boolean forceUserAuthorizationUriHttps = true;

    protected String loginEndpoint = "/j_spring_oauth2_login";

    protected String logoutEndpoint = "/j_spring_oauth2_logout";
    // DEFAULT VALUES - END -

    /** @return the cliendId */
    public String getCliendId() {
        return cliendId;
    }

    /** @param cliendId the cliendId to set */
    public void setCliendId(String cliendId) {
        this.cliendId = cliendId;
    }

    /** @return the clientSecret */
    public String getClientSecret() {
        return clientSecret;
    }

    /** @param clientSecret the clientSecret to set */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /** @return */
    public Boolean getForceAccessTokenUriHttps() {
        return forceAccessTokenUriHttps;
    }

    /** @param forceAccessTokenUriHttps */
    public void setForceAccessTokenUriHttps(Boolean forceAccessTokenUriHttps) {
        this.forceAccessTokenUriHttps = forceAccessTokenUriHttps;
    }

    /** @return the accessTokenUri */
    public String getAccessTokenUri() {
        return accessTokenUri;
    }

    /** @param accessTokenUri the accessTokenUri to set */
    public void setAccessTokenUri(String accessTokenUri) {
        this.accessTokenUri = accessTokenUri;
    }

    /** @return */
    public Boolean getForceUserAuthorizationUriHttps() {
        return forceUserAuthorizationUriHttps;
    }

    /** @param forceAccessTokenUriHttps */
    public void setForceUserAuthorizationUriHttps(Boolean forceUserAuthorizationUriHttps) {
        this.forceUserAuthorizationUriHttps = forceUserAuthorizationUriHttps;
    }

    /** @return the userAuthorizationUri */
    public String getUserAuthorizationUri() {
        return userAuthorizationUri;
    }

    /** @param userAuthorizationUri the userAuthorizationUri to set */
    public void setUserAuthorizationUri(String userAuthorizationUri) {
        this.userAuthorizationUri = userAuthorizationUri;
    }

    /** @return the redirectUri */
    public String getRedirectUri() {
        return redirectUri;
    }

    /** @param redirectUri the redirectUri to set */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /** @return the checkTokenEndpointUrl */
    public String getCheckTokenEndpointUrl() {
        return checkTokenEndpointUrl;
    }

    /** @param checkTokenEndpointUrl the checkTokenEndpointUrl to set */
    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    /** @return the logoutUri */
    public String getLogoutUri() {
        return logoutUri;
    }

    /** @param logoutUri the logoutUri to set */
    public void setLogoutUri(String logoutUri) {
        this.logoutUri = logoutUri;
    }

    /** @return the scopes */
    public String getScopes() {
        return scopes;
    }

    /** @param scopes the scopes to set */
    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    /**
     * **THIS MUST** be different for every OAuth2 Plugin
     *
     * @return
     */
    public String getLoginEndpoint() {
        return loginEndpoint;
    }

    /**
     * **THIS MUST** be different for every OAuth2 Plugin
     *
     * @return
     */
    public String getLogoutEndpoint() {
        return logoutEndpoint;
    }

    /** @param loginEndpoint */
    public void setLoginEndpoint(String loginEndpoint) {
        this.loginEndpoint = loginEndpoint;
    }

    /** @param logoutEndpoint */
    public void setLogoutEndpoint(String logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }

    /** @return the enableRedirectAuthenticationEntryPoint */
    public Boolean getEnableRedirectAuthenticationEntryPoint() {
        return enableRedirectAuthenticationEntryPoint;
    }

    /**
     * @param enableRedirectAuthenticationEntryPoint the enableRedirectAuthenticationEntryPoint to
     *     set
     */
    public void setEnableRedirectAuthenticationEntryPoint(
            Boolean enableRedirectAuthenticationEntryPoint) {
        this.enableRedirectAuthenticationEntryPoint = enableRedirectAuthenticationEntryPoint;
    }

    /**
     * Returns filter {@link AuthenticationEntryPoint} actual implementation
     *
     * @return {@link AuthenticationEntryPoint}
     */
    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return new AuthenticationEntryPoint() {

            @Override
            public void commence(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    AuthenticationException authException)
                    throws IOException, ServletException {
                final StringBuilder loginUri = new StringBuilder(getUserAuthorizationUri());
                loginUri.append("?")
                        .append("response_type=code")
                        .append("&")
                        .append("client_id=")
                        .append(getCliendId())
                        .append("&")
                        .append("scope=")
                        .append(getScopes().replace(",", "%20"))
                        .append("&")
                        .append("redirect_uri=")
                        .append(getRedirectUri());

                if (getEnableRedirectAuthenticationEntryPoint()
                        || request.getRequestURI().endsWith(getLoginEndpoint())) {
                    response.sendRedirect(loginUri.toString());
                }
            }
        };
    }

    @Override
    public boolean providesAuthenticationEntryPoint() {
        return true;
    }
}
