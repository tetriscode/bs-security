/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.GeoServerSecurityFilter;

/** @author Alessio Fabiani, GeoSolutions S.A.S. */
public class OracleOAuth2AuthenticationProvider extends GeoServerOAuthAuthenticationProvider {

    public OracleOAuth2AuthenticationProvider(
            GeoServerSecurityManager securityManager,
            String tokenServices,
            String oauth2SecurityConfiguration,
            String geoServerOauth2RestTemplate) {
        super(
                securityManager,
                tokenServices,
                oauth2SecurityConfiguration,
                geoServerOauth2RestTemplate);
    }

    @Override
    public void handlePostChanged(GeoServerSecurityManager securityManager) {
        // Nothing to do
    }

    @Override
    public void configure(XStreamPersister xp) {
        xp.getXStream().alias("oracleOauth2Authentication", OracleOAuth2FilterConfig.class);
    }

    @Override
    public Class<? extends GeoServerSecurityFilter> getFilterClass() {
        return OracleOAuthAuthenticationFilter.class;
    }

    @Override
    public GeoServerSecurityFilter createFilter(SecurityNamedServiceConfig config) {
        return new OracleOAuthAuthenticationFilter(
                config, tokenServices, oauth2SecurityConfiguration, geoServerOauth2RestTemplate);
    }
}
