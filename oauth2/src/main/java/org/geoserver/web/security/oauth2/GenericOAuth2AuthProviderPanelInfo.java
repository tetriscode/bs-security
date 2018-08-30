/* (c) 2018 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web.security.oauth2;

import org.geoserver.security.oauth2.GeoServerOAuthAuthenticationFilter;
import org.geoserver.security.oauth2.OAuth2FilterConfig;
import org.geoserver.security.web.auth.AuthenticationFilterPanelInfo;

/** Configuration panel extension for {@link GeoServerOAuthAuthenticationFilter}. */
public class GenericOAuth2AuthProviderPanelInfo
        extends AuthenticationFilterPanelInfo<OAuth2FilterConfig, GenericOAuth2AuthProviderPanel> {

    /** serialVersionUID */
    private static final long serialVersionUID = 4587996462800153425L;

    public GenericOAuth2AuthProviderPanelInfo() {
        setComponentClass(GenericOAuth2AuthProviderPanel.class);
        setServiceClass(GeoServerOAuthAuthenticationFilter.class);
        setServiceConfigClass(OAuth2FilterConfig.class);
    }
}
