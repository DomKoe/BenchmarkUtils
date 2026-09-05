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
 */
package org.owasp.benchmarkutils.score;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Verifies BenchmarkScore.calculateMetrics() correctly macro-averages overall Precision/F-score
 * (equal weight per category, consistent with how Score has always been computed) instead of
 * pooling raw counts, and correctly exposes a separate pooled/micro-averaged Score. Uses a fixture
 * with deliberately imbalanced category sizes (1000 / 20 / 100 test cases) and precision != TPR per
 * category, so the macro/pooled/mixed-formula distinctions are actually exercised rather than
 * accidentally masked by symmetric numbers.
 */
class CalculateMetricsTest {

    private static final double DELTA = 1e-9;

    private Map<String, TP_FN_TN_FP_Counts> buildImbalancedFixture() {
        Map<String, TP_FN_TN_FP_Counts> results = new LinkedHashMap<>();
        // TP_FN_TN_FP_Counts(tp, fn, tn, fp)
        results.put("Large Category", new TP_FN_TN_FP_Counts(90, 10, 800, 100));
        results.put("Small Category", new TP_FN_TN_FP_Counts(2, 8, 9, 1));
        results.put("Medium Category", new TP_FN_TN_FP_Counts(40, 10, 30, 20));
        return results;
    }

    @Test
    void overallPrecisionAndFScoreAreMacroAveraged() {
        ToolResults metrics = BenchmarkScore.calculateMetrics(buildImbalancedFixture());

        // Mean of each category's own precision/fscore (equal weight per category), not pooled
        // raw counts.
        assertEquals(0.6023391812865496, metrics.getPrecision(), DELTA);
        assertEquals(0.5518848967124829, metrics.getFScore(), DELTA);

        // Regression guard: the old (buggy) formula pooled raw TP/FP across categories before
        // dividing, which gives a different, size-dominated number. Confirm we're not back to
        // that.
        double oldPooledPrecision = 132.0 / (132.0 + 121.0);
        assertNotEquals(oldPooledPrecision, metrics.getPrecision(), DELTA);
    }

    @Test
    void overallScoreMicroAvgIsPooledAcrossTestCases() {
        ToolResults metrics = BenchmarkScore.calculateMetrics(buildImbalancedFixture());

        double pooledTPR = 132.0 / (132.0 + 28.0);
        double pooledFPR = 121.0 / (121.0 + 839.0);
        assertEquals(pooledTPR - pooledFPR, metrics.getOverallScoreMicroAvg(), DELTA);
    }

    @Test
    void overallScoreRemainsMacroAveraged() {
        ToolResults metrics = BenchmarkScore.calculateMetrics(buildImbalancedFixture());

        // Characterization test: Score (TPR - FPR) was already macro-averaged before this
        // change and must remain so - this arithmetic path is untouched by the fix.
        double macroTPR = (0.9 + 0.2 + 0.8) / 3.0;
        double macroFPR = (100.0 / 900.0 + 0.1 + 0.4) / 3.0;
        assertEquals(macroTPR - macroFPR, metrics.getOverallScore(), DELTA);
    }

    @Test
    void passThroughFieldsAreUnaffected() {
        ToolResults metrics = BenchmarkScore.calculateMetrics(buildImbalancedFixture());

        assertEquals(1120, metrics.getTotalTestCases());
        assertEquals(132, metrics.getFindingCounts().tp);
        assertEquals(121, metrics.getFindingCounts().fp);
        assertEquals(28, metrics.getFindingCounts().fn);
        assertEquals(839, metrics.getFindingCounts().tn);
    }
}
