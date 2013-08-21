package au.com.identityconcepts.shibboleth.wsfed;

/** Class for printing the version of this IdP. */
public final class Version {

    /** Name of the IdP. */
    private static final String NAME;

    /** IdP version. */
    private static final String VERSION;

    /** IdP major version number. */
    private static final int MAJOR_VERSION;

    /** IdP minor version number. */
    private static final int MINOR_VERSION;

    /** IdP micro version number. */
    private static final int MICRO_VERSION;

    /** Constructor. */
    private Version() {
    }

    /**
     * Main entry point to program.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        Package pkg = Version.class.getPackage();
        System.out.println(NAME + " version " + VERSION);
    }

    /**
     * Gets the name of the IdP.
     * 
     * @return name of the IdP
     */
    public static String getName() {
        return NAME;
    }

    /**
     * Gets the version of the IdP.
     * 
     * @return version of the IdP
     */
    public static String getVersion() {
        return VERSION;
    }

    /**
     * Gets the major version number of the IdP.
     * 
     * @return major version number of the IdP
     */
    public static int getMajorVersion() {
        return MAJOR_VERSION;
    }

    /**
     * Gets the minor version number of the IdP.
     * 
     * @return minor version number of the IdP
     */
    public static int getMinorVersion() {
        return MINOR_VERSION;
    }

    /**
     * Gets the micro version number of the IdP.
     * 
     * @return micro version number of the IdP
     */
    public static int getMicroVersion() {
        return MICRO_VERSION;
    }

    static {
        Package pkg = Version.class.getPackage();
        NAME = pkg.getImplementationTitle().intern();
        VERSION = pkg.getImplementationVersion().intern();
        String[] versionParts = VERSION.split("\\.");
        MAJOR_VERSION = Integer.parseInt(versionParts[0]);
        MINOR_VERSION = Integer.parseInt(versionParts[1]);
        MICRO_VERSION = Integer.parseInt(versionParts[2]);
    }
}