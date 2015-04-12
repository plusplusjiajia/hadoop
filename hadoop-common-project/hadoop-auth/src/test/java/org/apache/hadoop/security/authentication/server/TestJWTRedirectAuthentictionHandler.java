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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.hadoop.minikdc.KerberosSecurityTestcase;
import org.apache.hadoop.security.authentication.KerberosTestUtils;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestJWTRedirectAuthentictionHandler extends
    KerberosSecurityTestcase {
  private static final String SERVICE_URL = "https://localhost:8888/resource";
  private static final String REDIRECT_LOCATION =
      "https://localhost:8443/authserver?originalUrl=" + SERVICE_URL;
  RSAPublicKey publicKey = null;
  RSAPrivateKey privateKey = null;
  JWTRedirectAuthenticationHandler handler = null;

  @Test
  public void testNoPublicKeyJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(null);
      handler.setDecoder(decoder);
      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      assertTrue(token == null);
      fail("alternateAuthentication should have thrown a ServletException");
    } catch (ServletException se) {
      assertTrue(se.getMessage().contains(
          "Public key for signature validation must be provisioned"));
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testCustomCookieNameJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      props.put(JWTRedirectAuthenticationHandler.JWT_COOKIE_NAME, "jowt");
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("jowt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Assert.assertEquals("bob", token.getUserName());
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException: "
          + se.getMessage());
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testNoProviderURLJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      props
          .remove(JWTRedirectAuthenticationHandler.AUTHENTICATION_PROVIDER_URL);
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      fail("alternateAuthentication should have thrown an AuthenticationException");
    } catch (ServletException se) {
      assertTrue(se.getMessage().contains(
          "Authentication provider URL must not be null"));
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testUnableToParseJWT() throws Exception {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);

      KeyPair kp = kpg.genKeyPair();
      RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();

      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", "ljm" + tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Mockito.verify(response).sendRedirect(REDIRECT_LOCATION);
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testFailedSignatureValidationJWT() throws Exception {
    try {

      // Create a public key that doesn't match the one needed to
      // verify the signature - in order to make it fail verification...
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);

      KeyPair kp = kpg.genKeyPair();
      RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();

      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Mockito.verify(response).sendRedirect(REDIRECT_LOCATION);
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testExpiredJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() - 1000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Mockito.verify(response).sendRedirect(REDIRECT_LOCATION);
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testInvalidAudienceJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      props
          .put(JWTRedirectAuthenticationHandler.EXPECTED_JWT_AUDIENCES, "foo");
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Mockito.verify(response).sendRedirect(REDIRECT_LOCATION);
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown a AuthenticationException");
    }
  }

  @Test
  public void testValidAudienceJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      props
          .put(JWTRedirectAuthenticationHandler.EXPECTED_JWT_AUDIENCES, "bar");
      handler.init(props);

      AuthToken authToken = getAuthToken("bob", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Assert.assertEquals("bob", token.getUserName());
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown an AuthenticationException");
    }
  }

  @Test
  public void testValidJWT() throws Exception {
    try {
      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("alice", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      Mockito.when(request.getRequestURL()).thenReturn(
          new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
          SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
          response);
      Assert.assertNotNull("Token should not be null.", token);
      Assert.assertEquals("alice", token.getUserName());
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException.");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown an AuthenticationException");
    }
  }

  @Test
  public void testValidSingedAndEncryptedJWT() throws Exception {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);

      KeyPair kp = kpg.genKeyPair();
      RSAPublicKey encryptionKey = (RSAPublicKey) kp.getPublic();
      RSAPrivateKey decryptionKey = (RSAPrivateKey) kp.getPrivate();

      JwtTokenDecoder decoder = new JwtTokenDecoder();
      decoder.setVerifyKey(publicKey);
      decoder.setDecryptionKey(decryptionKey);
      handler.setDecoder(decoder);

      Properties props = getProperties();
      handler.init(props);

      AuthToken authToken = getAuthToken("alice", new Date(new Date().getTime() + 5000));
      JwtTokenEncoder tokenEncoder = new JwtTokenEncoder();
      tokenEncoder.setSignKey(privateKey);
      tokenEncoder.setEncryptionKey(encryptionKey);
      String tokenStr = tokenEncoder.encodeAsString(authToken);

      Cookie cookie = new Cookie("hadoop-jwt", tokenStr);
      HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
      Mockito.when(request.getCookies()).thenReturn(new Cookie[]{cookie});
      Mockito.when(request.getRequestURL()).thenReturn(
        new StringBuffer(SERVICE_URL));
      HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
      Mockito.when(response.encodeRedirectURL(SERVICE_URL)).thenReturn(
        SERVICE_URL);

      AuthenticationToken token = handler.alternateAuthenticate(request,
        response);
      Assert.assertNotNull("Token should not be null.", token);
      Assert.assertEquals("alice", token.getUserName());
    } catch (ServletException se) {
      fail("alternateAuthentication should NOT have thrown a ServletException.");
    } catch (AuthenticationException ae) {
      fail("alternateAuthentication should NOT have thrown an AuthenticationException");
    }
  }

  @Before
  public void setup() throws Exception, NoSuchAlgorithmException {
    setupKerberosRequirements();

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);

    KeyPair kp = kpg.genKeyPair();
    publicKey = (RSAPublicKey) kp.getPublic();
    privateKey = (RSAPrivateKey) kp.getPrivate();

    handler = new JWTRedirectAuthenticationHandler();
  }

  protected void setupKerberosRequirements() throws Exception {
    String[] keytabUsers = new String[] { "HTTP/host1", "HTTP/host2",
        "HTTP2/host1", "XHTTP/host" };
    String keytab = KerberosTestUtils.getKeytabFile();
    getKdc().createPrincipal(new File(keytab), keytabUsers);
  }

  @After
  public void teardown() throws Exception {
    handler.destroy();
  }

  protected Properties getProperties() {
    Properties props = new Properties();
    props.setProperty(
        JWTRedirectAuthenticationHandler.AUTHENTICATION_PROVIDER_URL,
        "https://localhost:8443/authserver");
    props.setProperty("kerberos.principal",
        KerberosTestUtils.getServerPrincipal());
    props.setProperty("kerberos.keytab", KerberosTestUtils.getKeytabFile());
    return props;
  }

  private AuthToken getAuthToken(String sub, Date expires) {
    AuthToken authToken = new JwtAuthToken();
    authToken.setSubject(sub);
    authToken.setIssueTime(new Date(new Date().getTime()));
    authToken.setIssuer("https://c2id.com");
    authToken.setExpirationTime(expires);
    List<String> aud = new ArrayList<String>();
    aud.add("bar");
    authToken.setAudiences(aud);
    return authToken;
  }
}
