/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @author Nipuna Weerasekara
 * @author Nicolas Couraud
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class CodeQLReader extends SarifReader {

    public CodeQLReader() {
        super("CodeQL", false, CweSourceType.TAG);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 94: // js/unsafe-dynamic-method-access & others - Improves the tool's score
                return CweNumber.COMMAND_INJECTION; // Command Injection
            case 234: // Two cpp rules are mapped to 234 & 685. But 234 is Discouraged so 685 is the
                // better mapping.
                // CWE-234: Failure to Handle Missing Parameter
                return 685; // CWE-685: Function Call With Incorrect Number of Arguments
            case 260: // cpp/cleartext-storage-file - Mapped to 260 and 313. 313 is a better
                // mapping.
                return 313; // CWE-313 Cleartext Storage in a File or on Disk
            case 335: // java/predictable-seed - Improves the tool's score
                return CweNumber.WEAK_RANDOM; // Weak Random
            case 401: // cpp/new-free-mismatch - CWE-401 is Missing Release of Memory
                return 762; // CWE-762: Mismatched Memory Management Routines (much better mapping)
            case 665: // cpp/uninitialized-local (Mapped to CWE-665: Improper Initialization and
                // CWE-457) 457 is a better mapping.
                return 457; // CWE-457: Use of Uninitialized Variable
        }
        return cwe;
    }

    /**
     * Override setVersion to include the version number of the 'codeql/java-queries' ruleset with
     * the version of the tool. Since both the tool version and the ruleset version can separately
     * affect the codeQL score.
     */
    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        JSONObject driver = toolDriver(firstRun(resultFile));

        String version = "unknown";
        if (driver.has("semanticVersion")) {
            version = driver.getString("semanticVersion");
        } else if (driver.has("version")) {
            version = driver.getString("version");
        }

        // Search for codeql/java-queries or codeql/cpp-queries ruleset version and add that to the
        // tool version
        try {
            JSONArray extensions =
                    firstRun(resultFile).getJSONObject("tool").getJSONArray("extensions");

            for (int i = 0; i < extensions.length(); i++) {
                JSONObject extension = extensions.getJSONObject(i);
                String name = extension.getString("name");
                if ("codeql/java-queries".equals(name) || "codeql/cpp-queries".equals(name)) {
                    // looking for:
                    // "semanticVersion": "1.1.9+de325133c7a95d84489acdf5a6ced07886ff5c6d",
                    String rulesetVersion = extension.getString("semanticVersion");
                    rulesetVersion = rulesetVersion.substring(0, rulesetVersion.indexOf('+'));
                    version += "_w" + rulesetVersion + "rules";
                }
            }
        } catch (JSONException e) {
            // Do nothing it if can't be found.
        }

        // Check if the extended ruleset is being used. If so, add '_extended' to version name
        // NOTE: This is VERY BRITTLE. We check for the presence of TWO Java specific rules that are
        // currently in the extended ruleset but not in the default. If they are both there, we add
        // _extended
        if (resultFile.content().contains("trust-boundary")
                && resultFile.content().contains("toctou-race-condition")) {
            version += "_extended";
        }

        // CodeQL for CPP has a security-extended ruleset, which is stronger than the
        // default ruleset. However, there is no indication in the ruleset version that
        // it is the stronger ruleset. So, we do the following hack to look for two
        // different security rules that are not present in the default ruleset and if
        // they are there, then we add _extended to the ruleset version.
        else if (resultFile.content().contains("cpp/unsafe-strcat")
                && resultFile.content().contains("cpp/overflow-buffer")) {
            version += "_extended";
        }

        testSuiteResults.setToolVersion(version);
    }
}
