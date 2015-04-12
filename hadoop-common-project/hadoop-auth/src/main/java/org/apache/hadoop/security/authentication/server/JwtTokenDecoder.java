/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.hadoop.security.authentication.server;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 * JWT token decoder, implemented using Nimbus JWT library.
 */
public class JwtTokenDecoder implements TokenDecoder {
  private static Logger LOG = LoggerFactory
    .getLogger(JwtTokenDecoder.class);

  private List<String> audiences = null;
  private static RSAPrivateKey decryptionKey = null;
  private static RSAPublicKey verifyKey = null;

  /**
   * set the verify key
   *
   * @param pk a public key
   */
  public void setVerifyKey(RSAPublicKey pk) {
    verifyKey = pk;
  }

  public RSAPublicKey getVerifyKey() {
    return verifyKey;
  }

  /**
   * Set the decryption key
   *
   * @param key a private key
   */
  public static void setDecryptionKey(RSAPrivateKey key) {
    decryptionKey = key;
  }

  public void setAudiences(List<String> auds) {
    audiences = auds;
  }

  @Override
  public AuthToken decodeAndValidate(byte[] content) throws IOException {
    String tokenStr = String.valueOf(content);
    return decodeAndValidate(tokenStr);
  }

  @Override
  public AuthToken decodeAndValidate(String serializedJWT) throws IOException {
    JwtAuthToken token = null;
    JWT jwt = null;
    try {
      jwt = JWTParser.parse(serializedJWT);
    } catch (ParseException e) {
      // Invalid JWT encoding
      LOG.warn("Unable to parse the JWT token string", e);
    }
    // Check the JWT type
    if (jwt instanceof PlainJWT) {
      PlainJWT plainObject = (PlainJWT) jwt;
      try {
        token = new JwtAuthToken(plainObject.getJWTClaimsSet());
      } catch (ParseException e) {
        LOG.warn("Unable to get the JWT claims set", e);
      }
    } else if (jwt instanceof EncryptedJWT) {
      EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
      decryptEncryptedJWT(encryptedJWT);
      SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
      if (signedJWT != null) {
        boolean valid = validateToken(signedJWT);
        if (valid) {
          LOG.debug("Issuing AuthenticationToken for user.");
          try {
            token = new JwtAuthToken(signedJWT.getJWTClaimsSet());
          } catch (ParseException e) {
            LOG.warn("Unable to get the JWT claims set", e);
          }
        } else {
          LOG.warn("jwtToken failed validation: " + signedJWT.serialize());
        }
      } else {
        try {
          token = new JwtAuthToken(encryptedJWT.getJWTClaimsSet());
        } catch (ParseException e) {
          LOG.warn("Unable to get the JWT claims set", e);
        }
      }
    } else if (jwt instanceof SignedJWT) {
      SignedJWT signedJWT = (SignedJWT) jwt;
      boolean valid = validateToken(signedJWT);
      if (valid) {
        LOG.debug("Issuing AuthenticationToken for user.");
        try {
          token = new JwtAuthToken(signedJWT.getJWTClaimsSet());
        } catch (ParseException e) {
          LOG.warn("Unable to get the JWT claims set", e);
        }
      } else {
        LOG.warn("jwtToken failed validation: " + signedJWT.serialize());
      }
    } else {
      LOG.warn("Unexpected JWT type: " + jwt);
    }
    return token;
  }

  /**
   * This method provides a single method for validating the JWT for use in
   * request processing. It provides for the override of specific aspects of
   * this implementation through submethods used within but also allows for the
   * override of the entire token validation algorithm.
   *
   * @param jwtToken
   * @return true if valid
   * @throws org.apache.hadoop.security.authentication.client.AuthenticationException
   */
  protected boolean validateToken(SignedJWT jwtToken) {
    boolean sigValid = validateSignature(jwtToken);
    if (!sigValid) {
      LOG.warn("Signature could not be verified");
    }
    boolean audValid = validateAudiences(jwtToken);
    if (!audValid) {
      LOG.warn("Audience validation failed.");
    }
    boolean expValid = validateExpiration(jwtToken);
    if (!expValid) {
      LOG.info("Expiration validation failed.");
    }

    return sigValid && audValid && expValid;
  }

  /**
   * Verify the signature of the JWT token in this method. This method depends
   * on the public key that was established during init based upon the
   * provisioned public key. Override this method in subclasses in order to
   * customize the signature verification behavior.
   *
   * @param jwtToken
   * @throws org.apache.hadoop.security.authentication.client.AuthenticationException
   */
  protected boolean validateSignature(SignedJWT jwtToken) {
    boolean valid = false;
    if (JWSObject.State.SIGNED == jwtToken.getState()) {
      LOG.debug("JWT token is in a SIGNED state");
      if (jwtToken.getSignature() != null) {
        LOG.debug("JWT token signature is not null");
        try {
          JWSVerifier verifier = new RSASSAVerifier(verifyKey);
          if (jwtToken.verify(verifier)) {
            valid = true;
            LOG.debug("JWT token has been successfully verified");
          } else {
            LOG.warn("JWT signature verification failed.");
          }
        } catch (JOSEException je) {
          LOG.warn("Error while validating signature", je);
        }
      }
    }
    return valid;
  }

  /**
   * Validate whether any of the accepted audience claims is present in the
   * issued token claims list for audience. Override this method in subclasses
   * in order to customize the audience validation behavior.
   *
   * @param jwtToken the JWT token where the allowed audiences will be found
   * @return true if an expected audience is present, otherwise false
   */
  protected boolean validateAudiences(SignedJWT jwtToken) {
    boolean valid = false;
    try {
      List<String> tokenAudienceList = jwtToken.getJWTClaimsSet()
        .getAudience();
      // if there were no expected audiences configured then just
      // consider any audience acceptable
      if (audiences == null) {
        valid = true;
      } else {
        // if any of the configured audiences is found then consider it
        // acceptable
        boolean found = false;
        for (String aud : tokenAudienceList) {
          if (audiences.contains(aud)) {
            LOG.debug("JWT token audience has been successfully validated");
            valid = true;
            break;
          }
        }
        if (!valid) {
          LOG.warn("JWT audience validation failed.");
        }
      }
    } catch (ParseException pe) {
      LOG.warn("Unable to parse the JWT token.", pe);
    }
    return valid;
  }

  /**
   * Validate that the expiration time of the JWT token has not been violated.
   * If it has then throw an AuthenticationException. Override this method in
   * subclasses in order to customize the expiration validation behavior.
   *
   * @param jwtToken
   * @throws org.apache.hadoop.security.authentication.client.AuthenticationException
   */
  protected boolean validateExpiration(SignedJWT jwtToken) {
    boolean valid = false;
    try {
      Date expires = jwtToken.getJWTClaimsSet().getExpirationTime();
      if (expires != null && new Date().before(expires)) {
        LOG.debug("JWT token expiration date has been "
          + "successfully validated");
        valid = true;
      } else {
        LOG.warn("JWT expiration date validation failed.");
      }
    } catch (ParseException pe) {
      LOG.warn("JWT expiration date validation failed.", pe);
    }
    return valid;
  }

  /**
   * Decrypt the Encrypted JWT
   *
   * @param encryptedJWT
   */
  public void decryptEncryptedJWT(EncryptedJWT encryptedJWT) throws IOException {
    RSADecrypter decrypter = new RSADecrypter(decryptionKey);
    try {
      encryptedJWT.decrypt(decrypter);
    } catch (JOSEException e) {
      LOG.warn("Failed to decrypt the encrypted JWT", e);
    }
  }
}
