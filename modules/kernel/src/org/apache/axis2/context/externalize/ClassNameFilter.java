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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * ClassNameFilter provides reflection-based access to JEP 290 Serialization Filtering
 * for Java 8 environments with the backport available in sun.misc.
 *
 * This abstract class dynamically creates and applies serialization filters to ObjectInputStream
 * instances to restrict which classes can be deserialized, mitigating deserialization
 * vulnerabilities.
 *
 * Implementations must provide the list of allowed classes via {@link #getDefaultAllowedClasses()}.
 */
public abstract class ClassNameFilter {

    private static final Log log = LogFactory.getLog(ClassNameFilter.class);

    // Reflection handles for JEP 290 Serialization Filtering
    private static Method createFilterMethod;
    private static Method setObjectInputFilterMethod;
    private static boolean isFilterAvailable = false;

    static {
        try {
            // Target the Java 8 backport classes located in sun.misc
            Class<?> filterClass = Class.forName("sun.misc.ObjectInputFilter");
            Class<?> configClass = Class.forName("sun.misc.ObjectInputFilter$Config");

            // Extract the necessary configuration methods via reflection
            createFilterMethod = configClass.getMethod("createFilter", String.class);
            setObjectInputFilterMethod = configClass.getMethod("setObjectInputFilter", ObjectInputStream.class, filterClass);
            
            isFilterAvailable = true;
        } catch (ClassNotFoundException e) {
            // JEP 290 framework is not available (running on an ancient Java 8 runtime)
            isFilterAvailable = false;
        } catch (Exception e) {
            isFilterAvailable = false;
        }
    }

    // Allowed classes list
    private final Set<String> allowedClasses;

    /**
     * Creates a new ClassNameFilter initialized with the default allowed classes.
     */
    protected ClassNameFilter() {
        Set<String> temp = new LinkedHashSet<String>();
        String[] defaultClasses = getDefaultAllowedClasses();
        if (defaultClasses != null) {
            for (String className : defaultClasses) {
                if (className != null && !className.isEmpty()) {
                    temp.add(className);
                }
            }
        }
        // Make immutable for thread safety
        this.allowedClasses = Collections.unmodifiableSet(temp);
    }

    /**
     * Returns the default allowed classes for this filter implementation.
     * Subclasses must provide the list of classes that are safe to deserialize.
     *
     * @return array of fully qualified class names that are allowed for deserialization
     */
    protected abstract String[] getDefaultAllowedClasses();

    /**
     * Checks if the serialization filter framework is available in the current JVM.
     *
     * @return true if JEP 290 filtering is supported, false otherwise
     */
    public static boolean isFilterAvailable() {
        return isFilterAvailable;
    }

    /**
     * Builds the filter pattern string from the allowed classes list.
     * Creates an allowed list pattern that rejects all other classes.
     *
     * @return the filter pattern string
     */
    private String buildPattern() {
        if (allowedClasses.isEmpty()) {
            return "!*"; // Reject everything if no classes are allowed
        }

        StringBuilder pattern = new StringBuilder();
        for (String className : allowedClasses) {
            // Validate class name format to prevent pattern injection
            if (className.contains(";") || className.contains("!")) {
                throw new IllegalArgumentException("Invalid class name contains pattern syntax: " + className);
            }
            if (pattern.length() > 0) {
                pattern.append(";");
            }
            pattern.append(className);
        }
        
        // Always reject all others (allowed list mode)
        pattern.append(";!*");
        
        return pattern.toString();
    }

    /**
     * Applies the current filter configuration to an ObjectInputStream.
     * 
     * @param ois the ObjectInputStream to apply the filter to
     * @throws IOException if filter creation or application fails
     */
    public void applyTo(ObjectInputStream ois) throws IOException {
        applyFilter(ois, buildPattern());
    }

    /**
     * Creates a filter from a pattern string and applies it to an ObjectInputStream.
     * This is a static utility method for direct pattern application.
     * 
     * Pattern syntax:
     * - Whitelist specific classes: "java.lang.String;java.util.Date"
     * - Reject all others: "!*"
     * - Combined: "java.lang.String;!*" (allow String, reject everything else)
     * 
     * @param ois the ObjectInputStream to apply the filter to
     * @param pattern the filter pattern string
     * @throws IOException if filter creation or application fails
     */
    public static void applyFilter(ObjectInputStream ois, String pattern) throws IOException {
        if (!isFilterAvailable) {
            // Log warning that JEP 290 filtering is unavailable
            if (log.isWarnEnabled()) {
                log.warn("JEP 290 deserialization filtering not available. " +
                         "Pre-loading checks will still apply, but post-instantiation " +
                         "filtering is disabled. Consider upgrading Java runtime.");
            }
            return;
        }

        try {
            // Equivalent to: ObjectInputFilter f = ObjectInputFilter.Config.createFilter(pattern);
            Object filterObject = createFilterMethod.invoke(null, pattern);
            
            // Equivalent to: ObjectInputFilter.Config.setObjectInputFilter(ois, f);
            setObjectInputFilterMethod.invoke(null, ois, filterObject);
        } catch (Exception e) {
            throw new IOException("Failed to apply serialization filter via reflection", e);
        }
    }

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
        description.append(", rejects all others. [Pattern: ").append(buildPattern()).append("]");
        return description.toString();
    }
}


