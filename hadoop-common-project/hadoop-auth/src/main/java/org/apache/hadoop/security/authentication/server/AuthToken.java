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

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This is the token definition API according to TokenPreauth draft.
 */
public interface AuthToken {

  /**
   * Get the token subject
   *
   * @return token subject
   */
  public String getSubject();

  /**
   * Set token subject
   *
   * @param sub
   */
  public void setSubject(String sub);

  /**
   * Get the token issuer
   *
   * @return token issuer
   */
  public String getIssuer();

  /**
   * Set token issuer
   *
   * @param issuer
   */
  public void setIssuer(String issuer);

  /**
   * Get token audiences
   *
   * @return token audiences
   */
  public List<String> getAudiences();

  /**
   * Set token audiences
   *
   * @param audiences
   */
  public void setAudiences(List<String> audiences);

  /**
   * Get token expired data time.
   *
   * @return expired time
   */
  public Date getExpiredTime();

  /**
   * Set token expired time
   *
   * @param exp
   */
  public void setExpirationTime(Date exp);

  /**
   * Get token not before time.
   *
   * @return not before time
   */
  public Date getNotBeforeTime();

  /**
   * Set token not before time.
   *
   * @param nbt
   */
  public void setNotBeforeTime(Date nbt);

  /**
   * Get token issued at time when the token is issued.
   *
   * @return issued at time
   */
  public Date getIssueTime();

  /**
   * Set token issued at time.
   *
   * @param iat
   */
  public void setIssueTime(Date iat);

  /**
   * Get token attributes.
   *
   * @return token attributes
   */
  public Map<String, Object> getAttributes();

  /**
   * Add a token attribute.
   *
   * @param name
   * @param value
   */
  public void addAttribute(String name, Object value);
}
