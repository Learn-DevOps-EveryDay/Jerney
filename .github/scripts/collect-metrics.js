const fs = require('fs');

function computeConditionMetrics(results, condName) {
  let totalScenarios = results.length;
  let depResPass = 0, depResSkip = 0;
  let buildPass = 0, buildSkip = 0;
  let testPass = 0, testSkip = 0;
  let rescanPass = 0, rescanSkip = 0;
  
  let validRecs = 0;
  let totalDistance = 0;
  let distanceCount = 0;
  let registryConfirmedCount = 0;

  for (const r of results) {
    const cond = r.conditions[condName];
    if (cond.registryConfirmed === true) registryConfirmedCount++;
    if (cond.patchDistance !== undefined && !isNaN(cond.patchDistance)) {
      totalDistance += cond.patchDistance;
      distanceCount++;
    }

    const gates = cond.gates;
    if (gates.dependencyResolution.status === 'pass') depResPass++;
    if (gates.dependencyResolution.status === 'skip') depResSkip++;
    
    if (gates.build.status === 'pass') buildPass++;
    if (gates.build.status === 'skip') buildSkip++;
    
    if (gates.test.status === 'pass') testPass++;
    if (gates.test.status === 'skip') testSkip++;
    
    if (gates.vulnerabilityRescan.status === 'pass') rescanPass++;
    if (gates.vulnerabilityRescan.status === 'skip') rescanSkip++;
  }

  const safeDivide = (num, den) => den === 0 ? null : parseFloat((num / den).toFixed(3));

  const depResValid = totalScenarios - depResSkip;
  const buildValid = totalScenarios - buildSkip;
  const testValid = totalScenarios - testSkip;
  const rescanValid = totalScenarios - rescanSkip;

  return {
    remediationSuccessRate: safeDivide(rescanPass, rescanValid),
    buildSuccessRate: safeDivide(buildPass, buildValid),
    testPassRate: safeDivide(testPass, testValid),
    dependencyConflictRate: safeDivide(depResValid > 0 ? (depResValid - depResPass) : 0, totalScenarios),
    averagePatchDistance: distanceCount > 0 ? parseFloat((totalDistance / distanceCount).toFixed(2)) : null,
    invalidRecommendationRate: safeDivide(totalScenarios - registryConfirmedCount, totalScenarios),
    counts: {
      totalScenarios,
      gatesPassed: {
        depResolution: depResPass,
        build: buildPass,
        test: testPass,
        rescan: rescanPass
      },
      gatesSkipped: {
        depResolution: depResSkip,
        build: buildSkip,
        test: testSkip,
        rescan: rescanSkip
      },
      registryConfirmed: registryConfirmedCount
    }
  };
}

function main() {
  const inputPath = process.argv[2] || 'experiment-results.json';
  const outputPath = process.argv[3] || 'thesis-metrics.json';

  console.log(`Calculating metrics from ${inputPath}...`);

  let data = { results: [] };
  try {
    data = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (err) {
    console.error('Failed to read experiment results:', err.message);
    process.exit(1);
  }

  const results = data.results;

  // Aggregate
  const aggregate = {
    deterministic: computeConditionMetrics(results, 'deterministic'),
    ai: computeConditionMetrics(results, 'ai')
  };

  // Per-component Breakdown
  const components = [...new Set(results.map(r => r.component))];
  const perComponent = {};
  for (const comp of components) {
    const compResults = results.filter(r => r.component === comp);
    perComponent[comp] = {
      deterministic: computeConditionMetrics(compResults, 'deterministic'),
      ai: computeConditionMetrics(compResults, 'ai')
    };
  }

  const finalMetrics = {
    experimentDate: new Date().toISOString(),
    totalScenarios: results.length,
    aggregate,
    perComponent
  };

  fs.writeFileSync(outputPath, JSON.stringify(finalMetrics, null, 2));
  console.log(`Metrics computed and saved to ${outputPath}`);
}

main();
