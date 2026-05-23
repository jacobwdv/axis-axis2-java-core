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

package org.apache.axis2.util;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * ClassNameFilter maintains an immutable allow-list of class names that are
 * permitted for deserialization checks.
 *
 * Implementations must provide the list of allowed classes via
 * {@link #getAllowedClasses()}.
 */
public abstract class ClassNameFilter {

    // Allowed classes list
    private final Set<String> allowedClasses;

    /**
     * Creates a new ClassNameFilter initialized with the allowed classes.
     */
    protected ClassNameFilter() {
        Set<String> temp = new LinkedHashSet<String>();
        String[] allowedClassNames = getAllowedClasses();
        if (allowedClassNames != null) {
            for (String className : allowedClassNames) {
                if (className != null && !className.isEmpty()) {
                    temp.add(className);
                }
            }
        }
        // Make immutable for thread safety
        this.allowedClasses = Collections.unmodifiableSet(temp);
    }

    /**
     * Returns the allowed classes for this filter implementation.
     * Subclasses must provide the list of classes that are safe to deserialize.
     *
     * @return array of fully qualified class names that are allowed for deserialization
     */
    protected abstract String[] getAllowedClasses();

    /**
     * Checks if a class name is allowed by this filter configuration.
     * This method performs the check WITHOUT loading the class, preventing
     * static initializer execution for malicious classes.
     *
     * @param className the fully qualified class name to check
     * @return true if the class is allowed, false if rejected
     */
    public boolean isClassAllowed(String className) {
        if (className == null) {
            return false;
        }
        
        // Check if explicitly allowed (exact match only)
        return allowedClasses.contains(className);
    }

    /**
     * Returns a human-readable description of the current filter configuration.
     *
     * @return a plain English description of what the filter allows and rejects
     */
    public String toString() {
        StringBuilder description = new StringBuilder(getClass().getSimpleName());
        description.append(": Allows ").append(allowedClasses.size()).append(" classes");
        description.append(", rejects all others.");
        return description.toString();
    }
}

