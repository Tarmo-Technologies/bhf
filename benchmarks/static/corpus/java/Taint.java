// M23 Phase 2: interprocedural taint for Java. A source-like parameter reaching
// a command sink (Runtime.exec / ProcessBuilder) is BHF-304 (proven flow). Java's
// BHF-404 heuristic fires on ANY exec, so the taint engine supersedes it at a
// confirmed site (dedup); the sanitized case shows BHF-404 alone (no escalation).
class Taint {
    void run(String userInput) throws Exception {
        Runtime.getRuntime().exec(userInput);   // EXPECT BHF-304
    }
    void dispatch(String userQuery) throws Exception {
        forward(userQuery);
    }
    void forward(String a) throws Exception {
        new ProcessBuilder(a).start();          // EXPECT BHF-304
    }
    void clean(String userPath) throws Exception {
        String v = sanitize(userPath);
        Runtime.getRuntime().exec(v);           // EXPECT BHF-404
    }
    void log(String userInput, org.slf4j.Logger logger) {
        logger.warn(userInput);                 // EXPECT BHF-544
        logger.info("fixed");
    }
}
