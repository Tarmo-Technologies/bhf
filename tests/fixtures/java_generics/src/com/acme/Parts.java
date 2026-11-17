// SPDX-License-Identifier: Apache-2.0
package com.acme;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;

/**
 * Targets that take JDK collections. Their harness locals are declared with
 * the parsed types (a {@code var} would infer the wrong element type) and
 * filled from the input, so each one compiles and fuzzes.
 *
 * The planted ArrayIndexOutOfBoundsException (BHF-201) is in {@code widths}: a
 * list of more than four parts overflows its table.
 */
public final class Parts {
    private Parts() {}

    public static int widths(List<String> parts) {
        int[] table = new int[4];
        for (int i = 0; i < parts.size(); i++) {
            table[i] = parts.get(i).length();
        }
        return table[0];
    }

    public static int fieldCount(Map<String, Object> fields) {
        return fields.size();
    }

    public static long total(int[] values) {
        long sum = 0;
        for (int value : values) {
            sum += value;
        }
        return sum;
    }

    public static int distinct(Set<Integer> ids) {
        return ids.size();
    }

    public static int firstBlobLength(SortedMap<String, byte[]> blobs) {
        return blobs.isEmpty() ? 0 : blobs.get(blobs.firstKey()).length;
    }

    public static int groupCount(List<Set<Integer>> groups) {
        int count = 0;
        for (Set<Integer> group : groups) {
            count += group.size();
        }
        return count;
    }

    public static int totalChars(Collection<? extends CharSequence> sequences) {
        int total = 0;
        for (CharSequence sequence : sequences) {
            total += sequence.length();
        }
        return total;
    }
}
