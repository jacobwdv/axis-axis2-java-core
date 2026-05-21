/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.axis2.context.externalize;

/**
 * IBM WebSphere implementation of ClassNameFilter.
 * Provides the default allowed classes for IBM WebSphere deserialization.
 *
 * This allowed list is derived from SecureObjectInputStream and includes
 * only the classes necessary for legitimate token propagation in IBM WebSphere.
 *
 * @see com.ibm.ws.wssecurity.platform.websphere.wssapi.token.impl.SecureObjectInputStream
 */
public class IbmClassNameFilter extends ClassNameFilter {

    /**
     * Default allowed classes for IBM WebSphere deserialization.
     */
    private static final String[] DEFAULT_ALLOWED_CLASSES = {
        // Token class hierarchy (3 levels)
        "com.ibm.ws.wssecurity.wssapi.token.impl.SecurityTokenImpl",
        "com.ibm.ws.wssecurity.wssapi.token.impl.UsernameTokenImpl",
        "com.ibm.ws.wssecurity.platform.websphere.wssapi.token.impl.WasUsernameTokenImpl",
        
        // Java standard classes used in token fields
        "java.lang.String",           // username, id, principal, referenceURI, keyIdentifier, keyName, thumbprint
        "java.lang.Boolean",          // isForwardable field
        "java.lang.Integer",          // HashMap keys in keyMap
        "java.util.Date",             // created timestamp field
        "java.util.HashMap",          // keyMap field (typically empty)
        
        // XML/QName classes for token metadata
        "javax.xml.namespace.QName",  // valueType, tokenQName, keyIdentifierEncodingType,
                                      // keyIdentifierValueType, thumbprintValueType, thumbprintEncodingType
        
        // Array types for binary data
        "[B",  // byte[] - nonce field
        "[C",  // char[] - password field
        
        // OMStructure for XML representation (typically null in token propagation)
        "com.ibm.ws.wssecurity.wssapi.OMStructure",
        "com.ibm.wsspi.wssecurity.wssapi.OMStructure"
    };

    /**
     * Creates a new IbmClassNameFilter with the default IBM WebSphere allowed classes.
     */
    public IbmClassNameFilter() {
        super();
    }

    /**
     * Returns the default allowed classes for IBM WebSphere deserialization.
     *
     * @return array of fully qualified class names that are allowed for deserialization
     */
    @Override
    protected String[] getDefaultAllowedClasses() {
        return DEFAULT_ALLOWED_CLASSES;
    }
}

