// SPDX-License-Identifier: Apache-2.0
// SQLite trade-study adapter (#255): run the input as SQL against an
// in-memory database. sqlite3_prepare_v2 compiles each statement; a progress
// handler and a row cap keep a slow statement from hanging the campaign.
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

static int stop_after_budget(void *steps) { return ++*(int *)steps > 20000; }

int target_one_input(const unsigned char *data, size_t size) {
    sqlite3 *db = NULL;
    char *sql = malloc(size + 1);
    if (sql == NULL) return 0;
    memcpy(sql, data, size);
    sql[size] = 0;
    if (sqlite3_open(":memory:", &db) == SQLITE_OK) {
        int steps = 0;
        sqlite3_progress_handler(db, 100, stop_after_budget, &steps);
        const char *next = sql;
        while (next != NULL && *next != 0) {
            sqlite3_stmt *stmt = NULL;
            const char *start = next;
            if (sqlite3_prepare_v2(db, start, -1, &stmt, &next) != SQLITE_OK) break;
            if (stmt != NULL) {
                for (int row = 0; row < 64 && sqlite3_step(stmt) == SQLITE_ROW; row++) {
                }
                sqlite3_finalize(stmt);
            } else if (next == start) {
                break;
            }
        }
    }
    sqlite3_close(db);
    free(sql);
    return 0;
}
