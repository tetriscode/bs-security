/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.web.security.oauth2;

import org.geoserver.security.oauth2.*;
import org.geoserver.security.oauth2.GeoServerOAuthAuthenticationFilter;
import org.geoserver.security.oauth2.OracleOAuth2FilterConfig;
import org.geoserver.security.web.auth.AuthenticationFilterPanelInfo;

/**
 * Configuration panel extension for {@link GeoServerOAuthAuthenticationFilter}.
 *
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 */
public class OracleOAuth2AuthProviderPanelInfo
        extends AuthenticationFilterPanelInfo<
                OracleOAuth2FilterConfig, OracleOAuth2AuthProviderPanel> {

    /** serialVersionUID */
    private static final long serialVersionUID = 75616833259749734L;

    public OracleOAuth2AuthProviderPanelInfo() {
        setComponentClass(OracleOAuth2AuthProviderPanel.class);
        setServiceClass(OracleOAuthAuthenticationFilter.class);
        setServiceConfigClass(OracleOAuth2FilterConfig.class);
    }
}
