/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.minikdc;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.service.AbstractService;
import org.apache.kerby.kerberos.kerb.admin.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.server.KdcServer;

import java.io.File;

public class HadoopMinKdcService extends AbstractService {
    private KdcServer kdcServer;
    private File confDir;
    private File workDir;
    private LocalKadmin kadmin;

    public HadoopMinKdcService(String name) {
        super(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop() {
    }

    @Override
    protected void serviceInit(Configuration conf) throws Exception {
        super.serviceInit(conf);
        kdcServer = new KdcServer(confDir);
        kdcServer.setWorkDir(workDir);
        kdcServer.init();
        LocalKadmin kadmin = new LocalKadminImpl(kdcServer.getKdcSetting(), kdcServer.getIdentityService());
        kadmin.checkBuiltinPrincipals();
    }

    @Override
    protected void serviceStart() throws Exception {
        kdcServer.start();
        super.serviceStart();
    }
}
