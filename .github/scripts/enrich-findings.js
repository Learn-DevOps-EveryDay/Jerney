const fs = require('fs');
const path = require('path');

async function fetchCisaKev() {
  const kevSet = new Set();
  try {
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (res.ok) {
      const data = await res.json();
      if (data.vulnerabilities) {
        for (const v of data.vulnerabilities) {
          kevSet.add(v.cveID);
        }
      }
    }
  } catch (err) {
    console.warn('Failed to fetch CISA KEV catalog:', err.message);
  }
  return kevSet;
}

async function fetchEpssScores(cveList) {
  const epssMap = {};
  if (!cveList || cveList.length === 0) return epssMap;

  // Batch requests (50 max per API limits)
  const batchSize = 50;
  for (let i = 0; i < cveList.length; i += batchSize) {
    const batch = cveList.slice(i, i + batchSize);
    const cveString = batch.join(',');
    try {
      const res = await fetch(`https://api.first.org/data/v1/epss?cve=${cveString}`);
      if (res.ok) {
        const data = await res.json();
        if (data.data) {
          for (const item of data.data) {
            epssMap[item.cve] = {
              epss: parseFloat(item.epss),
              percentile: parseFloat(item.percentile)
            };
          }
        }
      }
    } catch (err) {
      console.warn(`Failed to fetch EPSS batch:`, err.message);
    }
  }
  return epssMap;
}

async function main() {
  const inputDir = process.argv[2];
  const outputPath = process.argv[3] || 'enriched-findings.json';

  if (!inputDir) {
    console.error('Usage: node enrich-findings.js <grype-results-dir> <output-file>');
    process.exit(1);
  }

  const findings = [];
  const cveSet = new Set();
  const components = [];

  try {
    const files = fs.readdirSync(inputDir).filter(f => f.endsWith('-grype.json'));
    
    for (const file of files) {
      const component = file.replace('-grype.json', '');
      components.push(component);
      const data = JSON.parse(fs.readFileSync(path.join(inputDir, file), 'utf8'));

      if (data.matches) {
        for (const match of data.matches) {
          const vuln = match.vulnerability;
          const artifact = match.artifact;
          
          let ecosystem = 'unknown';
          if (artifact.type === 'npm') ecosystem = 'npm';
          else if (artifact.type === 'python') ecosystem = 'pypi';

          const cveId = vuln.id;
          if (cveId && cveId.startsWith('CVE-')) {
            cveSet.add(cveId);
          }

          findings.push({
            component,
            ecosystem,
            package: artifact.name,
            installedVersion: artifact.version,
            fixedVersions: vuln.fix && vuln.fix.versions ? vuln.fix.versions : [],
            fixState: vuln.fix && vuln.fix.state ? vuln.fix.state : 'unknown',
            severity: vuln.severity,
            cveId: cveId || 'unknown'
          });
        }
      }
    }
  } catch (err) {
    console.error('Error reading Grype results:', err);
  }

  console.log(`Found ${findings.length} total findings across ${components.length} components.`);
  
  const kevSet = await fetchCisaKev();
  console.log(`Fetched ${kevSet.size} CISA KEV entries.`);
  
  const epssMap = await fetchEpssScores(Array.from(cveSet));
  console.log(`Fetched EPSS scores for ${Object.keys(epssMap).length} CVEs.`);

  // Enrich findings
  for (const f of findings) {
    const epss = epssMap[f.cveId] || { epss: 0, percentile: 0 };
    f.epssScore = epss.epss;
    f.epssPercentile = epss.percentile;
    f.isKnownExploited = kevSet.has(f.cveId);
  }

  const output = {
    metadata: {
      scanDate: new Date().toISOString(),
      totalFindings: findings.length,
      componentsScanned: components
    },
    findings
  };

  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`Wrote enriched findings to ${outputPath}`);
}

main().catch(console.error);
