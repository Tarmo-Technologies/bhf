class Vuln { void h(String u, java.io.ObjectInputStream ois, java.sql.Statement st) throws Exception {
    Runtime.getRuntime().exec("sh -c " + u);              // EXPECT BHF-404
    st.executeQuery("SELECT * FROM t WHERE x=" + u);      // EXPECT BHF-419
    Object o = ois.readObject();                          // EXPECT BHF-421
    java.security.MessageDigest.getInstance("MD5");       // EXPECT BHF-422
    String apiKey = "AKIAsecretvalue1234";                // EXPECT BHF-429
} }
