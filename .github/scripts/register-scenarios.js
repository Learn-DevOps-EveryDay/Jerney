const fs = require('fs');

function determineConflictPotential(ecosystem, pkgName, fixedVersions) {
  if (fixedVersions && fixedVersions.length > 1) {
    return 'high';
  }
  if (ecosystem === 'npm') {
    const commonDeps = ['path', 'qs', 'cookie', 'send', 'lodash', 'debug', 'body-parser', 'mime'];
    if (commonDeps.some(d => pkgName.includes(d))) {
      return 'medium';
    }
  }
  return 'low';
}

function main() {
  const args = process.argv.slice(2);
  const inputPath = args.find(a => !a.startsWith('--')) || 'enriched-findings.json';
  const outputPath = args.filter(a => !a.startsWith('--'))[1] || 'scenarios.json';
  
  const minScenariosArg = args.find(a => a.startsWith('--min-scenarios='));
  const maxScenariosArg = args.find(a => a.startsWith('--max-scenarios='));
  
  const MIN_SCENARIOS = minScenariosArg ? parseInt(minScenariosArg.split('=')[1], 10) : 30;
  const MAX_SCENARIOS = maxScenariosArg ? parseInt(maxScenariosArg.split('=')[1], 10) : 40;

  let enriched = { findings: [] };
  try {
    enriched = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (err) {
    console.error('Failed to read enriched findings:', err.message);
    process.exit(1);
  }

  // Dedup findings: unique combination of component + package + cveId
  const uniqueFindings = [];
  const seen = new Set();
  for (const f of enriched.findings) {
    const key = `${f.component}|${f.package}|${f.cveId}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueFindings.push(f);
    }
  }

  // Filter 1: Must have a fix available
  let fixedFindings = uniqueFindings.filter(f => f.fixState === 'fixed' || f.fixState === 'fixed-not-deployed');

  const selectedScenarios = [];
  
  // Selection Logic
  function selectByCondition(condition) {
    const matching = fixedFindings.filter(condition);
    for (const match of matching) {
      if (selectedScenarios.length >= MAX_SCENARIOS) return;
      if (!selectedScenarios.some(s => s.component === match.component && s.package === match.package && s.cveId === match.cveId)) {
        selectedScenarios.push(match);
      }
    }
  }

  // Priority 1: Known Exploited
  selectByCondition(f => f.isKnownExploited);
  
  // Priority 2: CRITICAL && EPSS >= 0.1
  selectByCondition(f => f.severity === 'CRITICAL' && f.epssScore >= 0.1);

  // Priority 3: HIGH && EPSS >= 0.1
  selectByCondition(f => f.severity === 'HIGH' && f.epssScore >= 0.1);

  // Priority 4: HIGH (any EPSS)
  selectByCondition(f => f.severity === 'HIGH');

  // Priority 5: MEDIUM && EPSS >= 0.3
  selectByCondition(f => f.severity === 'MEDIUM' && f.epssScore >= 0.3);

  // If still under MIN_SCENARIOS, relax criteria: take remaining sorted by EPSS descending
  let relaxed = false;
  if (selectedScenarios.length < MIN_SCENARIOS) {
    relaxed = true;
    const remaining = fixedFindings.filter(f => !selectedScenarios.some(s => s.component === f.component && s.package === f.package && s.cveId === f.cveId));
    remaining.sort((a, b) => b.epssScore - a.epssScore);
    
    for (const match of remaining) {
      if (selectedScenarios.length >= MAX_SCENARIOS) break;
      selectedScenarios.push(match);
    }
  }

  // Format scenarios
  const scenarios = selectedScenarios.map((f, i) => {
    return {
      id: `S${String(i + 1).padStart(3, '0')}`,
      component: f.component,
      ecosystem: f.ecosystem,
      package: f.package,
      installedVersion: f.installedVersion,
      grypeFixVersion: f.fixedVersions[0] || '',
      severity: f.severity,
      cveId: f.cveId,
      epssScore: f.epssScore,
      epssPercentile: f.epssPercentile,
      isKnownExploited: f.isKnownExploited,
      conflictPotential: determineConflictPotential(f.ecosystem, f.package, f.fixedVersions)
    };
  });

  const output = {
    selectionCriteria: {
      minSeverity: 'HIGH',
      minEpssScore: 0.1,
      kevIncluded: true,
      relaxedForMinimum: relaxed
    },
    totalFindings: fixedFindings.length,
    selectedCount: scenarios.length,
    scenarios
  };

  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`Registered ${scenarios.length} scenarios. Saved to ${outputPath}`);
}

main();
