const fs = require('fs');
const path = require('path');

/**
 * generate-deterministic-fixes.js
 *
 * Reads pre-registered scenarios (which include grypeFixVersion from Grype scan)
 * and produces a deterministic remediation plan — using only Grype's own fix data.
 * This serves as the BASELINE condition in the experiment.
 *
 * Usage: node generate-deterministic-fixes.js <scenarios.json> <output-file>
 */

function main() {
  const scenariosPath = process.argv[2];
  const outputPath = process.argv[3] || 'deterministic-plan.json';

  console.log(`Reading scenarios from ${scenariosPath}...`);

  if (!scenariosPath) {
    console.error('Usage: node generate-deterministic-fixes.js <scenarios.json> <output-file>');
    fs.writeFileSync(outputPath, JSON.stringify({ condition: 'deterministic', recommendations: [] }, null, 2));
    process.exit(1);
  }

  let scenariosData = { scenarios: [] };
  try {
    scenariosData = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
  } catch (err) {
    console.error('Failed to read scenarios:', err.message);
    fs.writeFileSync(outputPath, JSON.stringify({ condition: 'deterministic', recommendations: [] }, null, 2));
    process.exit(1);
  }

  const recommendations = [];

  for (const scenario of scenariosData.scenarios) {
    if (!scenario.grypeFixVersion) {
      console.warn(`Scenario ${scenario.id}: No Grype fix version available. Skipping.`);
      continue;
    }

    // Determine the type based on ecosystem
    let type = 'dependencies';
    if (scenario.ecosystem === 'pypi') {
      type = 'requirements';
    }

    recommendations.push({
      scenarioId: scenario.id,
      component: scenario.component,
      ecosystem: scenario.ecosystem,
      package: scenario.package,
      currentVersion: scenario.installedVersion,
      recommendedVersion: scenario.grypeFixVersion,
      type: type,
      risk: 'low',
      reason: `Deterministic upgrade to Grype-recommended fix version ${scenario.grypeFixVersion} for ${scenario.cveId} (${scenario.severity}, EPSS: ${scenario.epssScore}).`
    });
  }

  const plan = {
    condition: 'deterministic',
    recommendations: recommendations
  };

  fs.writeFileSync(outputPath, JSON.stringify(plan, null, 2));
  console.log(`Generated deterministic plan with ${recommendations.length} recommendations.`);
}

main();
