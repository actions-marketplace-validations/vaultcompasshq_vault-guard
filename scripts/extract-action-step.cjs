#!/usr/bin/env node
// Prints one field of one composite step in action.yml, for a shell caller.
//
//   node scripts/extract-action-step.cjs <action.yml> <step name> run
//   node scripts/extract-action-step.cjs <action.yml> <step name> working-directory
//
// It exists so `scripts/test-action-path-validation.sh` can check PROPERTIES OF
// A STEP rather than properties of the file. Counting how many times
// `working-directory:` appears anywhere goes red the day somebody adds a third
// step that legitimately declares one, and a grep for a run-script line cannot
// tell which step it came from. The parser is the same one the jest suites and
// the dogfood harness use, so all three callers agree about what the file says.
//
// Writing the run script out also lets the shell run `bash -n` over it, which
// is the only way the "this file must parse on bash 3.2" claim is actually
// enforced rather than approximated by a grep for the idioms known to break it.

const { loadAction } = require('./lib/action-steps.cjs');

const [, , actionPath, stepName, field] = process.argv;

if (!actionPath || !stepName || !field) {
  process.stderr.write(
    'usage: extract-action-step.cjs <action.yml> <step name> <run|working-directory>\n',
  );
  process.exit(2);
}

let action;
try {
  action = loadAction(actionPath);
} catch (err) {
  process.stderr.write(`extract-action-step: ${err.message}\n`);
  process.exit(2);
}

if (!action.hasStep(stepName)) {
  process.stderr.write(`extract-action-step: no step named ${stepName} in ${actionPath}\n`);
  process.exit(1);
}

try {
  if (field === 'run') {
    process.stdout.write(action.extractRunScript(stepName));
  } else if (field === 'working-directory') {
    // Empty output means the step declares none, which the caller has to be
    // able to tell from "the runner temp": a step with no working-directory
    // runs at the workspace root, which is the head's own tree.
    process.stdout.write(action.extractStepWorkingDirectory(stepName));
  } else {
    process.stderr.write(`extract-action-step: unknown field ${field}\n`);
    process.exit(2);
  }
} catch (err) {
  process.stderr.write(`extract-action-step: ${err.message}\n`);
  process.exit(1);
}
