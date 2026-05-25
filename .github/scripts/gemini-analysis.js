const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

function findDependencyPaths(dependencies, targetPkg, currentPath = []) {
  if (!dependencies) return [];
  let paths = [];
  for (const [name, pkg] of Object.entries(dependencies)) {
    const newPath = [...currentPath, `${name}@${pkg.version || 'unknown'}`];
    if (name === targetPkg) {
      paths.push(newPath);
    }
    if (pkg.dependencies) {
      paths.push(...findDependencyPaths(pkg.dependencies, targetPkg, newPath));
    }
  }
  return paths;
}

function formatDependencyChain(pathArray) {
  if (!pathArray || pathArray.length === 0) return 'Not found in dependency graph';
  if (pathArray.length === 1) return pathArray[0];
  let res = pathArray[0] + '\n';
  for (let i = 1; i < pathArray.length; i++) {
    const isLast = i === pathArray.length - 1;
    const prefix = '  '.repeat(i - 1) + (isLast ? '└── ' : '├── ');
    res += prefix + pathArray[i] + (isLast ? '' : '\n');
  }
  return res;
}

async function getBestModel(apiKey) {
  try {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
    if (res.ok) {
      const data = await res.json();
      const availableModels = data.models.map(m => m.name);
      
      const preferences = [
        'models/gemini-2.0-flash',
        'models/gemini-2.0-flash-lite',
        'models/gemini-1.5-flash',
        'models/gemini-1.5-flash-latest',
        'models/gemini-1.5-pro'
      ];

      for (const pref of preferences) {
        if (availableModels.includes(pref)) {
          return pref.replace('models/', '');
        }
      }
    }
  } catch (err) {
    console.warn('Failed to query models. Falling back to gemini-2.0-flash', err.message);
  }
  return 'gemini-2.0-flash';
}

async function main() {
  const args = process.argv.slice(2);
  const scenariosPath = args[0] || 'scenarios.json';
  const graphsDir = args[1] || '.';
  const outputPath = args[2] || 'ai-plan.json';

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.error('GEMINI_API_KEY environment variable is missing.');
    process.exit(1);
  }

  let scenariosData = { scenarios: [] };
  try {
    scenariosData = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
  } catch (err) {
    console.error('Failed to read scenarios.json:', err.message);
    process.exit(1);
  }

  // Load graphs
  const graphs = {};
  try {
    const files = fs.readdirSync(graphsDir).filter(f => f.endsWith('-deps.json'));
    for (const file of files) {
      const component = file.replace('-deps.json', '');
      graphs[component] = JSON.parse(fs.readFileSync(path.join(graphsDir, file), 'utf8'));
    }
  } catch (err) {
    console.warn('Could not load dependency graphs:', err.message);
  }

  // Group scenarios by component
  const componentScenarios = {};
  for (const s of scenariosData.scenarios) {
    if (!componentScenarios[s.component]) {
      componentScenarios[s.component] = [];
    }
    
    // Attach chain
    if (s.ecosystem === 'npm' && graphs[s.component] && graphs[s.component].dependencies) {
      const paths = findDependencyPaths(graphs[s.component].dependencies, s.package);
      if (paths.length > 0) {
        paths.sort((a, b) => a.length - b.length);
        s.dependencyChain = formatDependencyChain(paths[0]);
      } else {
        s.dependencyChain = 'Not found in dependency graph';
      }
    } else if (s.ecosystem === 'pypi') {
       s.dependencyChain = 'Python requirements.txt flat dependency';
    }

    componentScenarios[s.component].push(s);
  }

  const resolvedModel = await getBestModel(apiKey);
  console.log(`Using Gemini Model: ${resolvedModel}`);

  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({
    model: resolvedModel,
    generationConfig: { responseMimeType: 'application/json' }
  });

  const finalRecommendations = [];

  for (const [component, scenariosList] of Object.entries(componentScenarios)) {
    console.log(`Analyzing ${scenariosList.length} scenarios for component: ${component}`);
    const ecosystem = scenariosList[0].ecosystem;

    const prompt = `You are a senior DevSecOps engineer.
Below are vulnerability scenarios for the "${component}" component (${ecosystem} ecosystem).
For each scenario, recommend a safe package version upgrade.

Scenarios:
${JSON.stringify(scenariosList, null, 2)}

Decision Tree:
1. Direct dependency → upgrade directly
2. Transitive dependency → prefer upgrading parent dependency
3. If parent upgrade not viable → use npm overrides (for npm) or version pin (for pypi)

For each scenario, provide:
- scenarioId: the scenario ID
- package: the package to upgrade
- recommendedVersion: the version string (e.g. "4.21.2", no ^ or ~ prefix)
- type: "dependencies", "devDependencies", "overrides", or "requirements"
- risk: "low", "medium", or "high"
- reason: explanation referencing EPSS/KEV data and dependency analysis

Return JSON: { "recommendations": [ { "scenarioId": "...", "package": "...", "recommendedVersion": "...", "type": "...", "risk": "...", "reason": "..." } ] }`;

    try {
      const response = await model.generateContent(prompt);
      const text = response.response.text();
      const parsed = JSON.parse(text);
      
      if (parsed && Array.isArray(parsed.recommendations)) {
        // Inherit component metadata for safety
        for (const rec of parsed.recommendations) {
          rec.component = component;
          rec.ecosystem = ecosystem;
          finalRecommendations.push(rec);
        }
      }
    } catch (err) {
      console.error(`Gemini analysis failed for component ${component}:`, err);
    }
  }

  const plan = {
    condition: 'ai',
    model: resolvedModel,
    recommendations: finalRecommendations
  };

  fs.writeFileSync(outputPath, JSON.stringify(plan, null, 2));
  console.log(`Successfully generated AI plan with ${finalRecommendations.length} recommendations. Saved to ${outputPath}`);
}

main().catch(err => {
  console.error('Fatal error in gemini-analysis:', err);
  process.exit(1);
});
