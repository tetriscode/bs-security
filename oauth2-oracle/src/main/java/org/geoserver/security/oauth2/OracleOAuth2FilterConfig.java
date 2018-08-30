/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

/** @author Alessio Fabiani, GeoSolutions S.A.S. */
public class OracleOAuth2FilterConfig extends OAuth2FilterConfig {

    /** serialVersionUID */
    private static final long serialVersionUID = -3551428051398501603L;

    public OracleOAuth2FilterConfig() {
        this.accessTokenUri =
                "https://oam.example.com/ms_oauth/oauth2/endpoints/oauthservice/tokens";
        this.userAuthorizationUri =
                "https://oam.example.com/ms_oauth/oauth2/endpoints/oauthservice/authorize";
        this.redirectUri = "http://localhost:8080/geoserver/web/";
        this.checkTokenEndpointUrl =
                "https://oam.example.comoam.example.com/ms_oauth/oauth2/endpoints/oauthservice/tokens";
        this.logoutUri = "https://oam.example.com/logout";
        this.scopes = "UserProfile.me";
        this.enableRedirectAuthenticationEntryPoint = false;
        this.forceAccessTokenUriHttps = true;
        this.forceUserAuthorizationUriHttps = true;
        this.loginEndpoint = "/j_spring_oauth2_oracle_login";
        this.logoutEndpoint = "/j_spring_oauth2_oracle_logout";
    }
}
