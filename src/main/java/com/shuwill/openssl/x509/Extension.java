package com.shuwill.openssl.x509;

public class Extension {

    protected final String id;
    protected final ExtensionContext extensionContext;

    public Extension(String id, ExtensionContext extensionContext) {
        this.id = id;
        this.extensionContext = extensionContext;
    }

    public String getId() {
        return id;
    }

    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public static class ExtensionBuilder{

        protected ExtensionContext _extensionContext;

    }
}
