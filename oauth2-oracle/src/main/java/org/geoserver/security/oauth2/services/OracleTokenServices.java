/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2.services;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import org.geoserver.security.oauth2.GeoServerOAuthRemoteTokenServices;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Remote Token Services for Google token details.
 *
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 */
public class OracleTokenServices extends GeoServerOAuthRemoteTokenServices {

    private String userProfileEndpoint;
    private String scope = "UserProfile.me";

    public OracleTokenServices() {
        tokenConverter = new OracleAccessTokenConverter();
        restTemplate = new RestTemplate();
        ((RestTemplate) restTemplate)
                .setErrorHandler(
                        new DefaultResponseErrorHandler() {
                            @Override
                            // Ignore 400
                            public void handleError(ClientHttpResponse response)
                                    throws IOException {
                                if (response.getRawStatusCode() != 400) {
                                    super.handleError(response);
                                }
                            }
                        });
    }

    @Override
    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        super.setCheckTokenEndpointUrl(checkTokenEndpointUrl);
        userProfileEndpoint =
                checkTokenEndpointUrl.replace(
                        "oauth2/endpoints/oauthservice/tokens", "resources/userprofile/me");
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken)
            throws AuthenticationException, InvalidTokenException {
        Map<String, Object> checkTokenResponse = checkToken(accessToken);

        if (checkTokenResponse.containsKey("error")) {
            logger.debug("check_token returned error: " + checkTokenResponse.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        if (checkTokenResponse.containsKey("successful")
                && !(boolean) checkTokenResponse.get("successful")) {
            logger.debug("check_token returned false: " + checkTokenResponse.get("successful"));
            throw new InvalidTokenException(accessToken);
        }
        transformToken(accessToken, checkTokenResponse);

        Assert.state(
                checkTokenResponse.containsKey("client_id"),
                "Client id must be present in response from auth server");
        return tokenConverter.extractAuthentication(checkTokenResponse);
    }

    private void transformToken(String accessToken, Map<String, Object> checkTokenResponse) {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", accessToken);

        Map<String, Object> userProfile = getForMap(userProfileEndpoint, formData, headers);
        logger.info("Retrieved user profile");

        checkTokenResponse.put("active", checkTokenResponse.get("successful"));
        checkTokenResponse.put("username", userProfile.get("username"));
        checkTokenResponse.put("scope", scope);
        checkTokenResponse.put("sub", userProfile.get("email"));
        checkTokenResponse.put("client_id", clientId);
        checkTokenResponse.put("email", userProfile.get("email"));

        //        {
        //            "active": true,
        //                "client_id": "l238j323ds-23ij4",
        //                "username": "jdoe",
        //                "scope": "read write dolphin",
        //                "sub": "Z5O3upPC88QrAjx00dis",
        //                "aud": "https://protected.example.net/resource",
        //                "iss": "https://server.example.com/",
        //                "exp": 1419356238,
        //                "iat": 1419350238,
        //                "extension_field": "twenty-seven"
        //        }
        //        String[] jwtParts = accessToken.split("\\.");
        //        Gson gson = new Gson();
        //        Type type = new TypeToken<Map<String, String>>(){}.getType();
        //        String headerJson = new String(Base64.decode(jwtParts[0].getBytes()));
        //        String bodyJson = new String(Base64.decode(jwtParts[1].getBytes()));
        //        String footerJson = new String(Base64.decode(jwtParts[2].getBytes()));
        //
        //        logger.info("JWT Header " + headerJson);
        //        logger.info("JWT Body " + bodyJson);
        //        logger.info("JWT Footer " + footerJson);
        //        Map<String, String> body;
        //
        //        try {
        //            body = gson.fromJson(bodyJson, type);
        //            checkTokenResponse.put("sub", body.get("sub"));
        //        } catch (Exception e) {
        //            logger.warn("Unable to parse JWT - ", e);
        //        }

    }

    private Map<String, Object> checkToken(String accessToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("assertion", accessToken);
        formData.add("scope", scope);
        formData.add("grant_type", "oracle-idm:/oauth/grant-type/resource-access-token/jwt");
        formData.add("oracle_token_action", "validate");
        //        formData.add("oracle_token_attrs_retrieval", "iss aud exp prn jti exp iat sub");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));

        return postForMap(checkTokenEndpointUrl, formData, headers);
    }

    private String getAuthorizationHeader(String clientId, String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    private Map<String, Object> postForMap(
            String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        ParameterizedTypeReference<Map<String, Object>> map =
                new ParameterizedTypeReference<Map<String, Object>>() {};
        return restTemplate
                .exchange(path, HttpMethod.POST, new HttpEntity<>(formData, headers), map)
                .getBody();
    }

    private Map<String, Object> getForMap(
            String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        ParameterizedTypeReference<Map<String, Object>> map =
                new ParameterizedTypeReference<Map<String, Object>>() {};
        return restTemplate
                .exchange(path, HttpMethod.GET, new HttpEntity<>(formData, headers), map)
                .getBody();
    }
}
