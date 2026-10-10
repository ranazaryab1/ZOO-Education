#!/usr/bin/env node

/**
 * Copy files from the legacy upload folders into the private storage folders.
 * The default mode is deliberately read-only; pass --apply to copy files.
 */
const fs = require('fs');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const migrations = [
    ['B-A-A-R/blog-uploads', 'storage/blog'],
    ['B-A-A-R/assignment-uploads', 'storage/assignments'],
    ['Books & Notes/books-uploads', 'storage/books'],
    ['B-A-A-R/entry-test-uploads', 'storage/entry-test'],
    ['Past Papers/past-papers-uploads', 'storage/past-papers'],
];

function printUsage() {
    console.log('Usage: node scripts/migrate-legacy-uploads.js [--apply]');
    console.log('');
    console.log('Default mode is a dry-run. --apply copies files without deleting or overwriting.');
}

function parseArgs(args) {
    let apply = false;
    for (const arg of args) {
        if (arg === '--apply') {
            apply = true;
        } else if (arg === '--help' || arg === '-h') {
            printUsage();
            process.exit(0);
        } else {
            console.error(`Unknown option: ${arg}`);
            printUsage();
            process.exitCode = 2;
            return null;
        }
    }
    return { apply };
}

function collectFiles(directory) {
    const files = [];
    if (!fs.existsSync(directory)) return files;

    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
            files.push(...collectFiles(entryPath));
        } else if (entry.isFile()) {
            files.push(entryPath);
        }
    }
    return files;
}

function relativeDestination(sourceRoot, destinationRoot, sourceFile) {
    return path.join(destinationRoot, path.relative(sourceRoot, sourceFile));
}

function migrate({ apply }) {
    const mode = apply ? 'APPLY' : 'DRY-RUN';
    const totals = { planned: 0, copied: 0, skipped: 0, missing: 0, errors: 0 };
    console.log(`Legacy upload migration (${mode})`);
    console.log(apply
        ? 'Copying files only; existing files will be left untouched.'
        : 'No files will be changed. Re-run with --apply to copy the listed files.');

    for (const [sourceRelative, destinationRelative] of migrations) {
        const sourceRoot = path.join(projectRoot, sourceRelative);
        const destinationRoot = path.join(projectRoot, destinationRelative);
        const files = collectFiles(sourceRoot);

        if (!fs.existsSync(sourceRoot)) {
            totals.missing += 1;
            console.log(`\nMISSING  ${sourceRelative}`);
            continue;
        }

        console.log(`\n${sourceRelative} -> ${destinationRelative}`);
        if (files.length === 0) {
            console.log('  (no files)');
            continue;
        }

        for (const sourceFile of files) {
            const destinationFile = relativeDestination(sourceRoot, destinationRoot, sourceFile);
            const displaySource = path.relative(projectRoot, sourceFile);
            const displayDestination = path.relative(projectRoot, destinationFile);
            totals.planned += 1;

            if (fs.existsSync(destinationFile)) {
                totals.skipped += 1;
                console.log(`  SKIP      ${displaySource} (destination exists: ${displayDestination})`);
                continue;
            }

            if (!apply) {
                console.log(`  WOULD COPY ${displaySource} -> ${displayDestination}`);
                continue;
            }

            try {
                fs.mkdirSync(path.dirname(destinationFile), { recursive: true });
                fs.copyFileSync(sourceFile, destinationFile, fs.constants.COPYFILE_EXCL);
                totals.copied += 1;
                console.log(`  COPIED    ${displaySource} -> ${displayDestination}`);
            } catch (error) {
                totals.errors += 1;
                console.error(`  ERROR     ${displaySource}: ${error.message}`);
            }
        }
    }

    console.log('\nReport');
    console.log(`  Files found: ${totals.planned}`);
    console.log(`  ${apply ? 'Copied' : 'Would copy'}: ${apply ? totals.copied : totals.planned - totals.skipped}`);
    console.log(`  Skipped (already present): ${totals.skipped}`);
    console.log(`  Missing source folders: ${totals.missing}`);
    console.log(`  Errors: ${totals.errors}`);
    if (!apply) console.log('\nDry-run complete. No files or directories were changed.');
    if (totals.errors > 0) process.exitCode = 1;
}

const options = parseArgs(process.argv.slice(2));
if (options) migrate(options);
