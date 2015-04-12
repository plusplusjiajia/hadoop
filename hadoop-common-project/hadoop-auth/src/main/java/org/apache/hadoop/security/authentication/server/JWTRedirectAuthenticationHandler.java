/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
package org.apache.hadoop.security.authentication.server;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.text.ParseException;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AltKerberosAuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.CertificateUtil;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

/**
 * The {@link JWTRedirectAuthenticationHandler} extends
 * AltKerberosAuthenticationHandler to add WebSSO behavior for UIs. The expected
 * SSO token is a JsonWebToken (JWT). The supported algorithm is RS256 which
 * uses PKI between the token issuer and consumer. The flow requires a redirect
 * to a configured authentication server URL and a subsequent request with the
 * expected JWT token. This token is cryptographically verified and validated.
 * The user identity is then extracted from the token and used to create an
 * AuthenticationToken - as expected by the AuthenticationFilter.
 *
 * <p/>
 * The supported configuration properties are:
 * <ul>
 * <li>authentication.provider.url: the full URL to the authentication server.
 * This is the URL that the handler will redirect the browser to in order to
 * authenticate the user. It does not have a default value.</li>
 * <li>public.key.pem: This is the PEM formatted public key of the issuer of the
 * JWT token. It is required for verifying that the issuer is a trusted party.
 * DO NOT include the PEM header and footer portions of the PEM encoded
 * certificate. It does not have a default value.</li>
 * <li>expected.jwt.audiences: This is a list of strings that identify
 * acceptable audiences for the JWT token. The audience is a way for the issuer
 * to indicate what entity/s that the token is intended for. Default value is
 * null which indicates that all audiences will be accepted.</li>
 * <li>jwt.cookie.name: the name of the cookie that contains the JWT token.
 * Default value is "hadoop-jwt".</li>
 * </ul>
 */
public class JWTRedirectAuthenticationHandler extends
    AltKerberosAuthenticationHandler {
  private static Logger LOG = LoggerFactory
      .getLogger(JWTRedirectAuthenticationHandler.class);

  public static final String AUTHENTICATION_PROVIDER_URL = "authentication.provider.url";
  public static final String PUBLIC_KEY_PEM = "public.key.pem";
  public static final String EXPECTED_JWT_AUDIENCES = "expected.jwt.audiences";
  public static final String JWT_COOKIE_NAME = "jwt.cookie.name";
  private static final String ORIGINAL_URL_QUERY_PARAM = "originalUrl=";
  private String authenticationProviderUrl = null;

  private String cookieName = "hadoop-jwt";
  private JwtTokenDecoder decoder;

  public JwtTokenDecoder setDecoder(JwtTokenDecoder de) {
    return decoder = de;
  }

  /**
   * Initializes the authentication handler instance.
   * <p/>
   * This method is invoked by the {@link AuthenticationFilter#init} method.
   *
   * @param config
   *          configuration properties to initialize the handler.
   *
   * @throws ServletException
   *           thrown if the handler could not be initialized.
   */
  @Override
  public void init(Properties config) throws ServletException {
    super.init(config);
    if(decoder == null) {
      decoder = new JwtTokenDecoder();
    }
    // setup the URL to redirect to for authentication
    authenticationProviderUrl = config
        .getProperty(AUTHENTICATION_PROVIDER_URL);
    if (authenticationProviderUrl == null) {
      throw new ServletException(
          "Authentication provider URL must not be null - configure: "
              + AUTHENTICATION_PROVIDER_URL);
    }

    // setup the public key of the token issuer for verification
    if (decoder.getVerifyKey() == null) {
      String pemPublicKey = config.getProperty(PUBLIC_KEY_PEM);
      if (pemPublicKey == null) {
        throw new ServletException(
            "Public key for signature validation must be provisioned.");
      }
      RSAPublicKey publicKey = CertificateUtil.parseRSAPublicKey(pemPublicKey);
      decoder.setVerifyKey(publicKey);
    }

    // setup the list of valid audiences for token validation
    List<String> audiences = null;
    String auds = config.getProperty(EXPECTED_JWT_AUDIENCES);
    if (auds != null) {
      // parse into the list
      String[] audArray = auds.split(",");
      audiences = new ArrayList<String>();
      for (String a : audArray) {
        audiences.add(a);
      }
    }
    decoder.setAudiences(audiences);

    // setup custom cookie name if configured
    String customCookieName = config.getProperty(JWT_COOKIE_NAME);
    if (customCookieName != null) {
      cookieName = customCookieName;
    }
  }

  @Override
  public AuthenticationToken alternateAuthenticate(HttpServletRequest request,
      HttpServletResponse response) throws IOException,
      AuthenticationException {

    AuthenticationToken token = null;
    String serializedJWT = null;
    HttpServletRequest req = (HttpServletRequest) request;
    serializedJWT = getJWTFromCookie(req);
    AuthToken authToken = null;
    if (serializedJWT == null) {
      String loginURL = constructLoginURL(request, response);
      LOG.info("sending redirect to: " + loginURL);
      ((HttpServletResponse) response).sendRedirect(loginURL);
    } else {
      authToken = decoder.decodeAndValidate(serializedJWT);
      if (authToken == null) {
        String loginURL = constructLoginURL(request, response);
        LOG.info("token validation failed - sending redirect to: " + loginURL);
        ((HttpServletResponse) response).sendRedirect(loginURL);
      } else {
        String userName = authToken.getSubject();
        token = new AuthenticationToken(userName, userName, getType());
      }
    }
    return token;
  }

  /**
   * Encapsulate the acquisition of the JWT token from HTTP cookies within the
   * request.
   *
   * @param req
   * @return serialized JWT token
   */
  protected String getJWTFromCookie(HttpServletRequest req) {
    String serializedJWT = null;
    Cookie[] cookies = req.getCookies();
    String userName = null;
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookieName.equals(cookie.getName())) {
          LOG.info(cookieName
              + " cookie has been found and is being processed");
          serializedJWT = cookie.getValue();
          break;
        }
      }
    }
    return serializedJWT;
  }

  /**
   * Create the URL to be used for authentication of the user in the absence of
   * a JWT token within the incoming request.
   *
   * @param request
   * @param response
   * @return url to use as login url for redirect
   */
  protected String constructLoginURL(HttpServletRequest request,
      HttpServletResponse response) {
    String delimiter = "?";
    if (authenticationProviderUrl.contains("?")) {
      delimiter = "&";
    }
    String loginURL = authenticationProviderUrl + delimiter
        + ORIGINAL_URL_QUERY_PARAM
        + request.getRequestURL().toString();
    return loginURL;
  }
}
