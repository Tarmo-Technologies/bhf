// Best-in-class: interprocedural taint now confirms MORE than command injection.
// A source-like value reaching a file-open is path traversal (BHF-405); built into
// a SQL query it is SQL injection (BHF-419); a parameterized query with a tainted
// bound argument is safe and must NOT fire.
package p

import (
	"database/sql"
	"os"
)

func readPath(userPath string) {
	os.Open(userPath) // EXPECT BHF-405
}

func dispatch(userInput string) {
	readPath(userInput)
}

func sqlBuild(userQuery string, db *sql.DB) {
	db.Query("SELECT * FROM t WHERE x=" + userQuery) // EXPECT BHF-419
}

func sqlSafe(userData string, db *sql.DB) {
	db.Query("SELECT * FROM t WHERE x=?", userData) // safe: parameterized
}
