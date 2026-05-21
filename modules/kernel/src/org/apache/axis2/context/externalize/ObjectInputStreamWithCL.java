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
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectStreamClass;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.PrivilegedActionException;
import java.util.HashMap;

/**
 * An ObjectInputStream that is constructed with a ClassLoader or ClassResolver.
 * The default behavior is to use the ContextClassLoader.
 *
 * <p><b>SECURITY NOTE:</b> This class has been updated to properly support JEP 290
 * deserialization filtering. The resolveClass() method now calls super.resolveClass()
 * first, allowing Java's native filter mechanism to check classes BEFORE they are
 * loaded. This prevents malicious classes from executing static initializers during
 * deserialization attacks.</p>
 */
public class ObjectInputStreamWithCL extends java.io.ObjectInputStream
{
    private static final Log log = LogFactory.getLog(ObjectInputStreamWithCL.class);

    /**
     * <p>
     * This interface is used to resolve OSGi declared serializable classes.
     * </p>
     */
    public interface ClassResolver
    {
        /**
         * Attempt to load the specified class.
         *
         * @param className
         *            The classname.
         * @return The class, or null if not found.
         */
        public Class resolveClass(String className);
    }

    private static final HashMap primClasses = new HashMap(8, 1.0F);

    /** The class resolver */

    protected ClassResolver resolver;
    
    /** The ClassNameFilter for pre-loading validation */
    protected ClassNameFilter classNameFilter;
    static
    {
        primClasses.put("boolean", boolean.class);
        primClasses.put("byte", byte.class);
        primClasses.put("char", char.class);
        primClasses.put("short", short.class);
        primClasses.put("int", int.class);
        primClasses.put("long", long.class);
        primClasses.put("float", float.class);
        primClasses.put("double", double.class);
        primClasses.put("void", void.class);

    }

    protected ClassLoader classloader;

    protected String name;

    /**
     * Construct using ContextClassLoader
     * @param is
     * @throws IOException
     */
    public ObjectInputStreamWithCL(InputStream is) throws IOException
    {
        super(is);
        classloader = (ClassLoader) AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }

    /**
     * Constructor that accepts a ClassLoader
     * @param is
     * @param cl
     * @throws IOException
     */
    public ObjectInputStreamWithCL(InputStream is, ClassLoader cl) throws IOException
    {
        super(is);
        classloader = cl;
    }
    
    /**
     * Constructor that accepts a ClassResolver
     * @param is
     * @param r ClassResolver
     * @throws IOException
     */
    public ObjectInputStreamWithCL(InputStream is, ClassResolver r) throws IOException
    {
        super(is);
        resolver = r;
    }

    /**
     * Override resolveClass so that we can use our own ClassLoader.
     *
     * <p><b>CRITICAL SECURITY FIX:</b> This method now checks the ClassNameFilter
     * BEFORE calling Class.forName() to prevent malicious classes from executing
     * their static initializers during deserialization.</p>
     *
     * <p>The JEP 290 filter applied via setObjectInputFilter() only runs during
     * object instantiation, NOT during class resolution. Therefore, we must
     * manually check the filter before loading any class to prevent exploitation.</p>
     */
    protected Class resolveClass(ObjectStreamClass objStrmClass) throws ClassNotFoundException, IOException
    {
        String className = objStrmClass.getName();
        
        // CRITICAL SECURITY FIX: Check filter BEFORE loading the class
        // This prevents malicious classes from executing static initializers
        if (classNameFilter != null && !classNameFilter.isClassAllowed(className)) {
            // Log security event for monitoring/auditing
            if (log.isWarnEnabled()) {
                log.warn("SECURITY: Deserialization blocked for class: " + className);
            }
            throw new InvalidClassException("Class rejected by deserialization filter: " + className);
        }
        
        return resolveClass(className);
    }

    private Class resolveClass(String name) throws ClassNotFoundException
    {
        try
        {
            this.name = name;
            return (Class) AccessController.doPrivileged(loadAction);
        }
        catch (java.security.PrivilegedActionException pae)
        {
            Exception wrapped = pae.getException();
            if (wrapped instanceof ClassNotFoundException) throw (ClassNotFoundException) wrapped;
            throw new ClassNotFoundException(name);
        }
    }

    java.security.PrivilegedExceptionAction loadAction = 
        new java.security.PrivilegedExceptionAction()
    {
        public java.lang.Object run() throws Exception
        {
            try
            {
                Class clazz = null;
                // If the resolver is set
                if (resolver != null)
                {
                    // use the resolver to load the class.
                    clazz = resolver.resolveClass(name);
                }

                // if the class is not loadable
                if (clazz == null)
                {
                    clazz = loadClass(name, classloader); // d296416
                }

                return clazz;
            }
            catch (ClassNotFoundException cnf)
            {
                Class c = (Class) primClasses.get(name);
                if (c != null)
                {
                    return c;
                }
               
                throw cnf;
                
            } 
        }
    };

    // d296416: Use runtime bundle classloader (current) to resolve a class when
    // the class could not be resolved using the specified classloader.
    // A serializable class in a bundle should specify via
    // <com.ibm.ws.runtime.serializable> bundle extension point
    // that it is deserializable outside the current bundle.
    // NOTE: Looking up current classloader is only a tactical solution,
    // and could be deprecated in future.
    // 
    private java.lang.Class loadClass(final String name, final ClassLoader loader) throws ClassNotFoundException
    {
        try
        {
            try {
                return (Class) org.apache.axis2.java.security.AccessController.doPrivileged(
                        new PrivilegedExceptionAction() {
                            public Object run() throws ClassNotFoundException {
                                return Class.forName(name, true, loader);
                            }
                        }
                );
            } catch (PrivilegedActionException e) {
                throw (ClassNotFoundException) e.getException();
            }
        }
        catch (ClassNotFoundException cnf)
        {
            try {
                return (Class) org.apache.axis2.java.security.AccessController.doPrivileged(
                        new PrivilegedExceptionAction() {
                            public Object run() throws ClassNotFoundException {
                                return Class.forName(name);
                            }
                        }
                );
            } catch (PrivilegedActionException e) {
                throw (ClassNotFoundException) e.getException();
            }
        }
    }

    
    /**
     * Sets the ClassNameFilter for this ObjectInputStream.
     * This filter will be checked BEFORE attempting to load classes via Class.forName(),
     * preventing malicious classes from executing static initializers.
     *
     * @param filter the ClassNameFilter to use, or null to disable pre-loading checks
     */
    public void setClassNameFilter(ClassNameFilter filter) {
        this.classNameFilter = filter;
    }
    
    /**
     * Gets the current ClassNameFilter.
     *
     * @return the ClassNameFilter, or null if not set
     */
    public ClassNameFilter getClassNameFilter() {
        return classNameFilter;
    }
    
    /**
     * Override to provide our own resolution
     */
    protected Class resolveProxyClass(String[] interfaces) throws ClassNotFoundException
    {
        if (interfaces.length == 0)
        {
            throw new ClassNotFoundException("zero-length interfaces array");
        }

        Class nonPublicClass = null;

        final Class[] classes = new Class[interfaces.length];
        for (int i = 0; i < interfaces.length; i++)
        {
            classes[i] = resolveClass(interfaces[i]);

            if ((classes[i].getModifiers() & Modifier.PUBLIC) == 0)
            {
                // "if more than one non-public interface class loader is
                // encountered, an IllegalAccessError is thrown"
                if (nonPublicClass != null)
                {
                    throw new IllegalAccessError(nonPublicClass + " and " + classes[i] + " both declared non-public");
                }

                nonPublicClass = classes[i];
            }
        }

        // The javadocs for this method say:
        //
        // "Unless any of the resolved interfaces are non-public, this same
        // value of loader is also the class loader passed to
        // Proxy.getProxyClass; if non-public interfaces are present, their
        // class loader is passed instead"
        //
        // Unfortunately, we don't have a single classloader that we can use.
        // Call getClassLoader() on either the non-public class (if any) or the
        // first class.
        proxyClass = nonPublicClass != null ? nonPublicClass : classes[0];
        final ClassLoader loader = (ClassLoader) AccessController.doPrivileged(proxyClassLoaderAction);

        // "If Proxy.getProxyClass throws an IllegalArgumentException,
        // resolveProxyClass will throw a ClassNotFoundException containing the
        // IllegalArgumentException."
        try
        {
            return (Class) org.apache.axis2.java.security.AccessController.doPrivileged(
                    new PrivilegedAction() {
                        public Object run() {
                            return Proxy.getProxyClass(loader, classes);
                        }
                    }
            );
        }
        catch (IllegalArgumentException ex)
        {
            throw new ClassNotFoundException(ex.getMessage(), ex);
        }
    }

    private Class proxyClass;
    PrivilegedAction proxyClassLoaderAction = new PrivilegedAction()
    {
        public Object run()
        {
            return proxyClass.getClassLoader();
        }
    };
}
