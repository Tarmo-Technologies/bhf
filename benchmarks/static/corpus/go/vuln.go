package p
import ("os/exec"; "os"; "crypto/md5"; "database/sql")
func h(u, up string, db *sql.DB) {
    exec.Command("sh", "-c", u)   // EXPECT BHF-404
    os.ReadFile(up)               // EXPECT BHF-405
    md5.New()                     // EXPECT BHF-422
    db.Query("SELECT * FROM t WHERE x=" + u)  // EXPECT BHF-419
}
